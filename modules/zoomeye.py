from dotenv import dotenv_values
from typing import Literal
import requests

URL = 'https://api.zoomeye.org/host/search'
HEADERS = {'API-KEY': dotenv_values('.env')['ZOOMEYE_API_KEY']}

error_messages = {
    400: "request invalid, validate usage and try again",
    401: "request not authenticated, API token is missing, invalid or expired",
    402: "credits of the account was insufficient",
    403: "request not authorized, credential was suspended, exceeded usage",
    404: "request failed, the specified resource does not exist",
    405: "request failed, the specified method was not allowed",
    500: "error occurred, we are notified",
    503: "the request source was not available"
}

Type = Literal['app', 'device', 'os', 'service', 'ip', 'cidr',
               'hostname', 'port', 'city', 'country', 'asn',
               'header', 'title', 'site']


def zoomEye(Filter: Type, name: str):
    response = apiRequest(Filter, name)
    if isinstance(response, int):
        if response in error_messages:
            return error_messages[response]
        else:
            return '{response}: error occurred'.format(response=response)
    else:
        return extract_info(response)


def apiRequest(Filter: Type, name: str)\
        -> (int | dict[str, object]):
    querystring = {'query': '{type}:{address}'.format(
        type=Filter, address=name)}
    response = requests.get(URL, headers=HEADERS,  # type: ignore
                            params=querystring)
    if response.status_code < 200 or response.status_code >= 300:
        return response.status_code

    headers = response.headers
    body = response.json()

    return {'headers': headers, 'body': body}


def extract_info(data) -> (dict[str, object]):
    return {
        'Date': data['headers']['Date'],
        'Body': data['body']
    }
