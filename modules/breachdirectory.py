from dotenv import dotenv_values
from typing import Literal
import requests

URL = 'https://breachdirectory.p.rapidapi.com/'
HEADERS = {
    'content-type': 'application/octet-stream',
    'X-RapidAPI-Key': dotenv_values('.env')['XRAPID_API_KEY'],
    'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com'
}


def checkEmail(email: str) -> (int |
                               dict[str, object] |
                               Literal['Rate Limit Reached']):
    response = apiRequest(email)
    if response == 429:
        return 'Rate Limit Reached'
    elif type(response) == int:
        return response
    else:
        return extract_info(response)


def apiRequest(email: str) -> (int | dict[str, object]):
    querystring = {'func': 'auto', 'term': email}
    response = requests.get(URL, headers=HEADERS, params=querystring)

    if response.status_code < 200 or response.status_code >= 300:
        return response.status_code

    headers = response.headers
    body = response.json()

    return {'headers': headers, 'body': body}


def extract_info(data) -> (dict[str, object]):
    return {
        'Date': data['headers']['Date'],
        'Requests-Remaining':
            data['headers']['X-RateLimit-Requests-Remaining'],
        'Found': data['body']['found'],
        'Result': data['body']['result']
    }
