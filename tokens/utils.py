import logging
import base64
import urllib.request
import urllib.parse
import sys
sys.path.insert(0, 'src/vendor')
import jwt

logger = logging.getLogger("tokensLogger")
logger.setLevel(logging.INFO)


def encode_secrets(id, secret):
    # base64 encode clientId and clientSecret
    auth_param = id + ":" + secret
    authorization_header = "Basic " + base64.b64encode(
        bytes(auth_param, "utf8")).decode("utf-8")
    return authorization_header


def create_payload(id, redirect_uri, code):
    # Create Payload for Authorization Data
    payload = {
        "grant_type": "authorization_code",
        "client_id": id,
        "scope": "profile",
        "redirect_uri": redirect_uri,
        "code": code
    }
    logger.info("payload to cognito endpoint: \n{}".format(payload))
    return payload


def create_headers(client_id, client_secret):
    # Create Authorization header
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        "Authorization": encode_secrets(client_id, client_secret)
    }
    logger.info("headers: {}".format(headers))
    return headers


def post_request(url, data, headers):
    data = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req) as f:
        response = f.read().decode('utf-8')
    logger.info("The tokens response is:\n{}".format(response))
    return response


def decode_tokens(data):
    try:
        decoded = jwt.decode(data, verify=False)
        logger.info("decoded json web token data: \n{}".format(decoded))
        return decoded
    except Exception as e:
        logger.error(
            "Could not decode jwt Tokens in payload, failed with error:\n{}".
            format(e))
        raise e
