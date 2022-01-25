import json
from os import environ
import sys
from urllib.parse import urlencode

import boto3 
from bottle import request, response
import requests


class Log:

    def info(self,*args,**kwargs):
        print(*args, **kwargs, file=sys.stderr)


class   AWSservice:
    """ Role to assume """
    def __init__(self, conf):

        self.name = conf.get('service','no_name') # reference only

        self.attributes = conf.get('attrs', [])
        self.groups = conf.get('groups', [])
        self.role = conf.get('role', 'Role_not_Configured')
        self.duration = conf.get('duration', 3600)


    def get_credentials(self, uname):
        """ Return assumed role credentials """
        
        sts = boto3.client('sts')

        ret = sts.assume_role(
            RoleArn = self.role,
            RoleSessionName = uname,
            DurationSeconds = self.duration
        )

        if not 'Credentials' in ret:
            self.log.info('Error: Assuming Role', ret)
            raise Exception('STS: Assume role failed')
        
        return { # return format for sts sigin.aws.amazon.com/federation
                'sessionId': ret['Credentials']['AccessKeyId'],
                'sessionKey': ret['Credentials']['SecretAccessKey'],
                'sessionToken': ret['Credentials']['SessionToken']
            }


class AWScons:
    """ Bottle API to generate AWS Console URL """

    def __init__(self, app, auth, aws_config={}, log=None):

        self.log = log
        if not self.log: self.log = Log()

        url_prefix = aws_config.get('url_prefix', '/aws')
        route_url = url_prefix + '/<service_name>'

        aws_credentials_path = aws_config.get('aws_credentials_file')
        if aws_credentials_path:
            self.log.info(f'Using shared credentials file "{aws_credentials_path}"')
            environ['AWS_SHARED_CREDENTIALS_FILE'] = aws_credentials_path
        
        aws_profile_name = aws_config.get('aws_profile_name')
        if aws_profile_name:
            self.log.info(f'Using AWS profile "{aws_profile_name}"')
            environ['AWS_PROFILE'] = aws_profile_name
        

        self.timeout = aws_config.get('timeout', 200.0)
        
        self.targets = {}
        targets = aws_config.get('targets',[])
        for target in targets:
            cnf = AWSservice(target)
            self.targets[cnf.name] = cnf
        
        self.aws_signin_url = 'https://signin.aws.amazon.com/federation'
        self.aws_console_url = 'https://console.aws.amazon.com/'

        # Add route to handle Console URL request:
        self.log.info(f'Configuring route {route_url}')

        @app.route(route_url)
        @auth.require_login
        def handler(service_name):
            """ API endpoint to create AWS Console URL """
            
            session = request.session
            user = session.get('username')

            ip = request_ip()

            if service_name in self.targets:

                target_service = self.targets[service_name]
                if self.validate_user(user, target_service):

                    try:
                        url = self._get_console_url(user, ip, target_service)
                        response.status = 301
                        response.add_header('Location', url)
                        set_no_cache_headers()
                        return ''

                    except Exception as e:
                        # Authenticated and Authorized, but still failed.
                        self.log.info(e)
                        response.status=400
                        return str(e)

                else:
                    # NOT AUTHORIZED (401)
                    emsg = f'Request failed: for "{user}" - not authorized for service "{service_name}"'
                    self.log.info(emsg)
                    response.status = 401 
                    return emsg

            else:
                # NOT FOUND (404) - we don't have such a resource
                response.status = 404
                emsg = f'Request failed: user "{user}" - unknown service "{service_name}"'
                self.log.info(emsg)
                return emsg


    def _request_signin_token(self, session_creds, duration=3600):
        """ Form URL requesting signin token """

        args = {
            'Action': 'getSigninToken',
            'SessionDuration': duration,
            'Session': json.dumps(session_creds)
        }
        url = self.aws_signin_url + '?' + urlencode(args, doseq=True)  
        return url
    

    def _request_console_login(self, signin_token, reqip):
        """ Creating URL requesting signed console login. """

        args = {
            'Action': 'login',
            'Issuer': reqip,
            'Destination': self.aws_console_url,
            'SigninToken': signin_token
        }
        return self.aws_signin_url + '?' + urlencode(args, doseq=True,)# quote_via=quote)


    def _get_console_url(self, uname, reqip, service):
        """ Get a console login URL """

        # Get credentials, maybe assume the role
        session_creds = service.get_credentials(uname)
        
        #  build the token request and fetch the sign-in token
        url = self._request_signin_token(session_creds, duration=service.duration)
        
        r = requests.get(url, timeout=self.timeout)
        if r.status_code != 200:
            self.log.info('Error: Getting SigninToken', r.url)
            self.log.info(r.content)
            raise Exception(f'Bad response requesting signin token {r.reason}')
        
        sin_token = r.json()['SigninToken']

        # build the console signin url
        sin_url = self._request_console_login(sin_token, reqip)

        return sin_url


    def validate_user(self, user, contxt):
        """Validate user has required group membership and attributes."""

        # Check requestor for membership in authorized groups
        groups_pass = False
        if contxt.groups:
            memberships = request.session['attributes']['groups']

            for group in memberships:
                if group in contxt.groups:
                    self.log.info(f'User {user} has Membership ({group}) Authorization for "{contxt.name}"')
                    groups_pass = True
                    # one is good enough
                    break
        else:
            # no group restriction
            groups_pass = True

        # Validate requestor has at least one of the required attribute list
        attr_pass = False        
        if groups_pass and contxt.attributes:
            attributes = self.session['attributes']
            
            for attr in contxt.attributes:
                if attr in attributes and attributes[attr]:
                    self.log.info(f'User {user} has Required Attribute ({attr}) Authorization for "{contxt.name}"')
                    attr_pass = True
                    # one is good enough
                    break
        else:
            # no required attribute restriction
            attr_pass = True

        if not groups_pass:
            self.log.info(f'User {user} NOACCESS: missing required membership for "{contxt.name}"')

        elif not attr_pass:
            self.log.info(f'User {user} NOACCESS: missing attribute for "{contxt.name}"')

        else:
            self.log.info(f'User {user} PERMITTED for "{contxt.name}"')

        # User has required attributes: True or False
        return attr_pass and groups_pass


def request_ip():
    """ 
    Get the requestors IP address
    """
    # if no x-forwarded-for we assume local mode and localhost
    cfc_ip = request.headers.get('cf-connecting-ip',"")
    xff_ip = request.headers.get('x-forwarded-for', "").split(',')[0].strip()
    if xff_ip or cfc_ip:
        ip = xff_ip or cfc_ip
    else:
        ip = request.remote_addr
    
    return ip


def set_no_cache_headers():
    """
    Set various "no cache" headers for this response
    """

    # MDN recommended for various browsers
    response.add_header('Cache-Control', 'no-cache')
    response.add_header('Cache-Control', 'must-revalidate')
    response.add_header('Pragma', 'no-cache')
    response.add_header('Expires', 'Sun, 25 Jul 2021 15:42:14 GMT')
