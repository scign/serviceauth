import logging
from authtoken import get_youtube_token, get_zoom_token
import azure.functions as func

"""
Must be deployed WITH authentication (i.e. function keys)
"""

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

    token_functions = {
        'youtube': get_youtube_token,
        'zoom': get_zoom_token
    }
    try:
        token_func = token_functions.get(name)
        token = token_func()
        return func.HttpResponse(token)
    except KeyError:
        return func.HttpResponse(
             "Pass a name in the query string or in the request body for a token.",
             status_code=400
        )
