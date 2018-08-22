import jwt
import logging
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

import config

logger = logging.getLogger()


def wrap_public_key(public):
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % public


def validate(access_token):
    # This is validation resource server should do
    # If there is any claim is not valid, there will be an exception
    payload = jwt.decode(access_token.encode('ascii'), public_key, audience=config.RESOURCE, algorithms=alg)
    logger.debug("Access token is validated, and details are:")
    for k, v in payload.items():
        logger.debug("%s: %s", k, v)


# General preparation
keys = requests.get('https://fs.ersa.edu.au/adfs/discovery/keys').json()
assert len(keys['keys']) == 1
alg = keys['keys'][0]['alg']
x5c = keys['keys'][0]['x5c'][0]
pub_key = wrap_public_key(x5c)
cert_obj = load_pem_x509_certificate(pub_key.encode('ascii'), backend=default_backend())
public_key = cert_obj.public_key()
