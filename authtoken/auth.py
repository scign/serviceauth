import os
import jwt
import requests
import logging
from datetime import datetime, timedelta

def get_jwt(issuer, scopes = [], uri='', key='', algo='RS256'):
    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=3600)
    jwt_headers = {'alg':algo,'typ':'JWT'}
    jwt_claim = {
        'iss':issuer,
        'scope':' '.join(scopes),
        'aud':uri,
        'exp':exp,
        'iat':iat
    }
    logging.info(f"Generating JWT at {iat.isoformat()} for expiry at {exp.isoformat()}")
    return jwt.encode(jwt_claim, key, algorithm=algo, headers=jwt_headers)

def get_youtube_token(full_response=False):
    logging.info('Attempting to get YouTube token')
    token_uri = 'https://oauth2.googleapis.com/token'
    svc_account = os.environ.get('GOOGLE_SERVICE_ACCOUNT','')
    private_key = os.environ.get('GOOGLE_PRIVATE_KEY','')
    scopes = [
        'https://www.googleapis.com/auth/youtube',
        'https://www.googleapis.com/auth/youtube.readonly',
        'https://www.googleapis.com/auth/youtubepartner',
        'https://www.googleapis.com/auth/yt-analytics.readonly',
        'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
    ]
    logging.info(f"YouTube service account: {svc_account[:10]}...")
    logging.info(f"YouTube private key: {private_key[:10]}...")
    myjwt = get_jwt(
        issuer=svc_account,
        scopes=scopes,
        uri=token_uri,
        key=private_key.encode('utf-8')
    )
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r_token = requests.post(
        token_uri,
        data='grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer' + '&assertion=' + myjwt,
        headers=headers
    )
    if full_response:
        return r_token
    else:
        logging.info(f'Sent JWT token, received status code {r_token.status_code}')
        if r_token.status_code==200:
            logging.info(f"Access token ({r_token.json()['token_type']}) expires in {r_token.json()['expires_in']} seconds")
            return r_token.json()['access_token']
        else:
            logging.error(f"Access token request failed with status code {r_token.status_code}")
            try:
                logging.info(f"Request response JSON: {r_token.json()}")
            except:
                pass
            return ''

def get_zoom_token(full_response=False):
    api_key = os.environ.get('ZOOM_API_KEY','')
    api_secret = os.environ.get('ZOOM_API_SECRET','')
    logging.info(f"YouTube service account: {svc_account[:10]}...")
    logging.info(f"YouTube private key: {private_key[:10]}...")
    myjwt = get_jwt(
        issuer=api_key,
        key=api_secret.encode('utf-8'),
        algo='HS256'
    )
    return myjwt

