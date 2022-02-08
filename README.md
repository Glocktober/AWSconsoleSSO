# AWScons - AWS Console SSO Access Manager

AWScon provides Single Sign On (SSO) users with AWS console access restricted by AWS IAM roles.  Single Sign On is provided by SAML2, and role access is restricted by group membership.


## Deployment Options

* `AWScons` has been developed ant tested with **Apache** and **mod_wsgi**.
* The SAML IdP used for Single Sign On (SSO) is Microsoft Azure AD

* **However** `AWScons` should be usable with any WSGI compliant web server environment and any SAML2 compatible IdP.

* You will need have the requisite skills for your web server and IdP to deploy this app, as it is impossible to cover and test all the variations, or to document them here.

## Installation of Python Components

```bash
 % git clone https://github.com/Glocktober/AWSconsoleSSO.git
 % cd AWSconsoleSSO
 % python3 -m venv
 % source venv/bin/activate
 % pip install -r requirements.txt
 % # Create config.py
 % # start for test on <hostname>:8000/
 % python3 app.py
```

* This will install the `AWScons` app and it's required components.
* Generally you will want to deploy into a *venv* virtual environment.
* You still need to integrate the Python code into your WSGI web application service and your SAML IdP.
* Python components:
 * [Bottle](http://bottlepy.org/docs/dev/) WSGI web application server
 * [BottleSaml](https://github.com/Glocktober/BottleSaml) SAML2 Service Provider for Bottle using [minisaml](https://github.com/HENNGE/minisaml)
 * [BottleSessions](https://github.com/Glocktober/BottleSessions) provides session state management for Bottle using the *Pallets Project* [cachelib](https://pypi.org/project/cachelib/)
 * Additional more common component packages such as *requests*, *cryptography*,  and *boto3*
## Setup AWS IAM user and roles

### Create one or more AWS Assumed Roles

In AWS IAM 
* create a role selecting "For Another AWS Account".
* Use the account number of the Assuming User (this can be the same, or a different account as the role.)
* Attach the desired policy for this role.
* Set the maximum duration this role can be used (the default is 1 hour)
* Keep track of the ARN

Repeat this for each role you want to create.

For example, you can create a role called `MyAdminRole` in your account with the id of 123456789012, providing that same account id as the accessing account. Then attach the AWS managed policy `AdministratorAccess`, and edit the role to change the maximum duration to 8 hours (28800 seconds).  The role ARN will be `arn:aws:iam::123456789012:role/MyAdminRole`.

In a different account (999999789012) you can create a role called `DBAdminRole`, listing account 123456789012 as the trusted account. Then attach the AWS managed policy `AWSRDSFullAccess`.  The role ARN will be `arn:aws:iam::999999789012:role/DBAdminRole`.

The key is that the created roles must have trusted access to the account that will be generating the assume role credentials.

### Create An AWS Policy to Assume the Created Roles

Create a policy with `sts:AssumeRole` API access to the ARNs for the assumed roles created in the previous step.  This is done in the account that was granted the trust to assume any of the roles you created.

In our example this was account 123456789012. So in account 123456789012 you would create a policy - we'll call it `assumeSSOpolicy`:
``` json
 {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:assumeRole",
            "Resource": [
                "arn:aws:iam::123456789012:role/MyAdminRole",
                "arn:aws:iam::123456789012:role/ReadOnlyRole",
                "arn:aws:iam::999999789012:role/DBAdminRole",
            ]
        }
    ]
}
```


### Create a User or Role with this Policy

Apply the policy in one of two ways:
* Attach the policy to an EC2 IAM Role and attach to the EC2 instance `AWScons` is hosted.
* Attach the policy directly to an IAM user account.

For EC2:
* In IAM create a new role, for EC2, and attach the policy (`assumeSSOpolicy` in our example) to this role.
* Attache this role to the EC2 instance the code will be running on.

For IAM user:
* Create an IAM user (say `AWSconSSO`) with only API keys and save the keys
* Apply the policy (`assumeSSOpolicy` in our example) to this user
* On the hosting sever create a credentials file containing the API keys
* Use the config options `aws_credentials_file` and `aws_profile` in the aws_config stanza of config.py

The EC2 Role is the preferred method when `AWScons` is hosted in AWS; the IAM User account is required if `AWScons` is not being hosted in AWS, or hosted with outher API applications.

## Create the config.py Configuration File

An example file is provided `config.py.sample'. You can use this file as a framework to create a config.py file that will be located in the same directory as the `AWScons` app.py file.


There are three sections in the config.py file:
* session_config - user session configuration
* saml_config - SAML SP configuration
* aws_config - maps url path to specific roles to assume

### Configure `session_config` stanza
* This can be a simple null configuration in many cases:
```
session_config = {}
```
* For higher use environments you will want persistent caching.  Consult [BottleSessions](https://github.com/Glocktober/BottleSessions) documentation for more detail.
* With a low-volume of requests the memory-based SimpleCache is adequate
* With a higher-volume of requests FileCache is simple enough with only a path to a cache directory specified

### Configure `saml_config` stanza
* Configuring the SAML Service Provider (SP) is beyond the scope of this document. Refer to [BottleSaml](https://github.com/Glocktober/BottleSaml) documentation for more detail. 
* The `name_id` configured should be something useful (username or email), as it will be included in console and also in CloudTrail logging. 
* If `groups` will be used for authorization, these should be provided as IdP assertions, and listed in the `assertions` configuration list so they will be kept as session attributes.

### Configure `aws_config` 
* This provides configuation options and url path to role mapping

#### Application Configuration Settings

These options are for the full AWScons instance.

| **parameter**  |**type** | **default** | **description**
|------------------|-----|--------|----------------------|
|**url_prefix**|String|""|Prefix for target URLS (defaults to no URL prefix)|
|**aws_profile_name**|String|None|For IAM user creds - sets `AWS_PROFILE`|
|**aws_credentials_file**|String|None|For IAM user creds - sets `AWS_SHARED_CREDENTIALS_FILE`|
|**targets**|List|None|Python Dict containing specific target entries|

* One or more **targets** can be included in the AWScons instance.  Only the **targets** list is required.

#### Target Specific Configuration Settings

A target configuration item contains specific information for a given service.
| **parameter**  |**type** | **default** | **description**
|------------------|-----|--------|----------------------|
|**service**|String|None (required)|Name of service target used as URL path |
|**duration**|Integer|3600|Duration (Seconds) credentials for assumed role are valid|
|**role**|String|None (required)|ARN of role assumed for this URL path|
|**groups**|[String,..]|[]|User must have membership in one or more of these groups|

* `duration` can not exceed the maximum duration associated with the specified IAM `role`
* `groups` is a list of groups restricting access to this role
* The specific `service` is invoked when the final component of the url path matches the `service` name.  i.e. https://www.example.com/aws/myadmin' matches the service target with the name 'myadmin' (but only when the instance has the url_prefix of '/aws') 

#### Example 1: A Basic aws_config Stanza:
``` python
aws_config = {
      "targets" : [{
            "service": "awsadm", 
            "role": "arn:aws:iam::123456789012:role/MyAdminRole",
        } ]
}
```
Accessing https://www.example.com/awsadm will launch an AWS console to any authenticated user. The console will have access of the `MyAdminRole` role in account `123456789012`. The console and credentials will be valid for 1 hour.


#### Example 2: A More Complex aws_config Stanza:
``` python
aws_config = {
      "url_prefix": "/aws",         # Base for URL
      "aws_profile_name" : "cons",  # Profile name     
      "aws_credentials_file" : "/usr/local/.aws/credentials",     # Credentials file 
      "targets" : [
            {
                  "service": "cloudadmin",  # /aws/cloudadmin
                  "role": "arn:aws:iam::123456789012:role/MyAdminRole",
                  "duration": 28800,
                  "groups" : ["sysadmin", "cloudadmin"]
            },
            {
                  "service": "sandbox",     # /aws/sandbox
                  "role": "arn:aws:iam::999999789012:role/DBAdmin",
                  "duration": 28800,
                  "groups" : ["dbs"]
            } 
      ]
}
```
This config uses API credentials with the specified credentials file and profile name; all target URLs are prefixed with /aws.

Accessing https://www.example.com/aws/cloudadmin, an authenticated user must be a member of either `sysadmin` or `cloudadmin` groups. The user will be provided a console with the privileges of `MyAdminRole` that will be valid for 8 hours. The account accessed will be 123456789012.

With https://www.example.com/aws/sandbox, the authenticated user must be a member of the group `dba'. The privileges will be thoses of DBAdmin, and provides access to the AWS account with the id of 999999789012. 

### Evaluation and Generation of Console URL
* The specific target is evaluated when a GET request is made to the URL path matching the form /<url_prefix>/<service>
* If a match is not found the request failes with an HTML 401 Unknown error.
* The user is `authenticated` via SAML, with the IdP provided assertions added to user session as attributes for `authorization`. This includes 'groups' list.
* The user is authorized if:
 * The user is a member of at least one group specified in the `groups` of the target configuration. 
 * If no groups are listed in the target config, the user is not rejected.
 * Failing to meet this, the request fails with an HTML 403 Unauthorized error
* `AWScons` acquires temporary credentials for `role` specified in the target config using the AWS sts:AssumeRole API
* `AWScons` then calls AWS sts to generate a console login token
* The login token is formed to a logon URL
* The login URL is returned as an HTML 301 redirect 


