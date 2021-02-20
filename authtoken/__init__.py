import os
import jwt
import requests
import logging
from datetime import datetime, timedelta
import azure.functions as func


"""
Must be deployed WITH authentication (i.e. function key)
"""

def get_youtube_token(full_response=False):
    logging.info('Attempting to get YouTube token')
    private_key = os.environ.get('PRIVATE_KEY','').encode('utf-8')
    svc_account = os.environ.get('SERVICE_ACCOUNT','')
    token_uri = 'https://oauth2.googleapis.com/token'
    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=3600)
    jwt_headers = {'alg':'RS256','typ':'JWT'}
    scopes = [
        'https://www.googleapis.com/auth/youtube',
        'https://www.googleapis.com/auth/youtube.readonly',
        'https://www.googleapis.com/auth/youtubepartner',
        'https://www.googleapis.com/auth/yt-analytics.readonly',
        'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
    ]
    jwt_claim = {
        'iss':svc_account,
        'scope':' '.join(scopes),
        'aud':token_uri,
        'exp':exp,
        'iat':iat
    }
    encoded = jwt.encode(jwt_claim, private_key, algorithm='RS256', headers=jwt_headers)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r_token = requests.post(
        token_uri,
        data='grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer' + '&assertion=' + encoded,
        headers=headers
    )
    if full_response:
        return r_token
    else:
        logging.info(f'Sent JWT token, received status code {r_token.status_code}')
        if r_token.status_code==200:
            logging.info(f"Access token generated at {iat.isoformat()} for expiry at {exp.isoformat()}")
            logging.info(f"Access token ({r_token.json()['token_type']}) expires in {r_token.json()['expires_in']} seconds")
            return r_token.json()['access_token']
        else:
            logging.error(f"Access token request failed with status code {r_token.status_code}")
            try:
                logging.info(f"Request response JSON: {r_token.json()}")
            except:
                pass
            return ''

def main(req: func.HttpRequest) -> str:
    """
    Get an authenticated access token from the named service
    Parameters:
    name: ['zoom','youtube']
    returns: authenticated link
    """
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError as ve:
            logging.error(ve)
        else:
            name = req_body.get('name')

    if name=='youtube':
        token = get_youtube_token()
        return func.HttpResponse(token)
    else:
        return func.HttpResponse(
             "Pass a name in the query string or in the request body for a token.",
             status_code=400
        )
