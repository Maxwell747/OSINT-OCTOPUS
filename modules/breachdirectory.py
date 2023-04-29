from dotenv import dotenv_values
import requests

KEY = dotenv_values('.env')['XRAPID_API_KEY']
URL = 'https://breachdirectory.p.rapidapi.com/'
HEADERS = {
    'content-type': 'application/octet-stream',
    'X-RapidAPI-Key': KEY,
    'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com'
}


def checkEmail(email: str) -> int | str | dict[str, object]:
    querystring = {'func': 'auto', 'term': email}
    response = requests.get(URL, headers=HEADERS, params=querystring)

    if response.status_code == 429:
        return 'Request limit reached'
    if response.status_code < 200 or response.status_code >= 300:
        return response.status_code

    headers = response.headers
    body = response.json()

    return {'headers': headers, 'body': body}
