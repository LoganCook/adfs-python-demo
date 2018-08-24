import adal
import flask
import uuid
import config
import logging
from adal.constants import OAuth2
from decode import validate
import requests

OAuth2.IdTokenMap['email'] = 'email'
OAuth2.IdTokenMap['unique_name'] = 'name'

# Make adal loggin visible
logging.basicConfig(level=logging.DEBUG)


# export FLASK_APP=app.py
# export FLASK_DEBUG=1
# flask run -p 44320

app = flask.Flask(__name__)
app.debug = True
app.secret_key = 'development'

PORT = 44320  # A flask app by default runs on PORT 5000
AUTHORITY_URL = config.AUTHORITY_HOST_URL
REDIRECT_URI = 'http://localhost:{}/signin-oidc'.format(PORT)
TEMPLATE_AUTHZ_URL = ('{}/oauth2/authorize?' +
                      'response_type=code&client_id={}&redirect_uri={}&' +
                      # to get userinfo, call to authorize needs scope=openid and
                      # acquire_token_with_authorization_code cannot set resource
                      # userinfo endpoint has only sub(ject).
                      # no scope other than openid will bring in extra claims under
                      # current set up.
                      # 'state={}&scope=openid')
                      'state={}&resource=' + config.RESOURCE)


@app.route("/")
def main():
    login_url = 'http://localhost:{}/login'.format(PORT)
    resp = flask.Response(status=307)
    resp.headers['location'] = login_url
    return resp


@app.route("/login")
def login():
    auth_state = str(uuid.uuid4())
    flask.session['state'] = auth_state
    authorization_url = TEMPLATE_AUTHZ_URL.format(
        AUTHORITY_URL,
        config.CLIENT_ID,
        REDIRECT_URI,
        auth_state)
    resp = flask.Response(status=307)
    resp.headers['location'] = authorization_url
    return resp


@app.route("/signin-oidc")
def main_logic():
    code = flask.request.args['code']
    state = flask.request.args['state']
    if state != flask.session['state']:
        raise ValueError("State does not match")
    auth_context = adal.AuthenticationContext(AUTHORITY_URL, False)
    # for a resource
    token_response = auth_context.acquire_token_with_authorization_code(code, REDIRECT_URI, config.RESOURCE,
    # # for userinfo
    # token_response = auth_context.acquire_token_with_authorization_code(code, REDIRECT_URI, None,
                                                                        config.CLIENT_ID, config.CLIENT_SECRET)
    # demo of how to validate access_token
    validate(token_response['accessToken'])

    flask.session['access_token'] = token_response['accessToken']
    header = {'Authorization': 'Bearer ' + token_response['accessToken']}

    res = requests.get('http://localhost:8000/account/', headers=header)
    # if set up for userinfo endpoint, use this redirect
    # return flask.redirect('/userinfo')
    return flask.render_template('display_accounts.html', content={'accounts': res.json(), 'token': token_response})


if __name__ == "__main__":
    app.run()
