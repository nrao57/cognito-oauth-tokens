import os
import json
import boto3
import logging
import base64
import urllib.request
import urllib.parse
from tokens.utils import create_payload, create_headers, decode_tokens
import sys
sys.path.insert(0, 'src/vendor')
import requests

redirect_uri = os.getenv('REDIRECT_URI')
url = os.getenv('COGNITO_TOKENS_ENDPOINT')
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')

logger = logging.getLogger("tokensLogger")
logger.setLevel(logging.INFO)


def get_tokens(event, context):
    logger.info("The triggering event: \n{}".format(event))

    try:
        # get authorization code from event
        if event.get("queryStringParameters") is None:

            return {
                "statusCode":
                400,
                'headers': {
                    'Access-Control-Allow-Origin': '*'
                },
                "body":
                json.dumps({
                    "message":
                    "No authorization_code in the queryStringParameters of the event"
                })
            }

        # Proceed If there is an authorization_code in the event
        authorization_code = event.get("queryStringParameters").get(
            "authorization_code")
        logger.info(
            "Authorization Code in the Query String Parameters: \n{}".format(
                authorization_code))

        # Create Payload and headers for the request
        authData = create_payload(client_id, redirect_uri, authorization_code)
        headers = create_headers(client_id, client_secret)

        response = requests.post(url, data=authData, headers=headers)
        logger.info(
            "Response from POST request to COGNITO_TOKENS_ENDPOINT: \n{}".
            format(response.json()))

        # Decode the response jwt tokens to get user information
        user_info = decode_tokens(response.json().get('id_token'))
        user_info["idToken"] = response.json().get('id_token')
        logger.info("User Info: \n{}".format(user_info))

        # create a response
        response = {
            "statusCode": 200,
            'headers': {
                'Access-Control-Allow-Origin': '*'
            },
            "body": json.dumps(user_info)
        }

        logger.info("Returned Response: \n{}".format(response))

    except Exception as e:
        logger.error(e)
        raise e

    return response
