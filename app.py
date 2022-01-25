import json
import os

from bottle import request, response, Bottle

from BottleSessions import BottleSessions
from BottleSaml import SamlSP

from AWScons import AWScons

from config import saml_config, session_config, aws_config

DEBUG=os.environ.get('DEBUG',False)

app = Bottle()
sess = BottleSessions(app, **session_config)

saml = SamlSP(app, sess=sess, saml_config=saml_config)
AWScons(app, saml, aws_config)

@app.route('/<path:path>')
def other(path=None):
    response.status = 401
    return 'Not Found'

if DEBUG:
    @app.route('/.whoami')
    def index():
        return f'Hello {request.session.get("username","Anonymous")}'


    @app.route('/.login')
    @saml.require_login
    def login():
        """Force login"""
        return f'Hello {request.session.get("username","Anonymous")}'


    @app.route('/.sess')
    def get_sess():
        response.content_type = "application/json"
        return json.dumps(request.session, indent=4)


if __name__ == '__main__':
    app.run(host='localhost', port=8000, debug=DEBUG, reloader=DEBUG)
else:
    application = app
