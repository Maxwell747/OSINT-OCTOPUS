from dotenv import dotenv_values
import requests

KEY = dotenv_values('.env')['BUILTWITH_API_KEY']


def builtWith(domain: str) -> (int | dict[str, object]):
    response = apiRequest(domain)
    if type(response) == int:
        return response
    else:
        return extract_info(response)


def apiRequest(domain: str) -> (int | dict[str, object]):
    query = \
        'https://api.builtwith.com/free1/api.json?KEY={key}&LOOKUP={domain}'\
        .format(key=KEY, domain=domain)
    response = requests.get(query)

    if response.status_code < 200 or response.status_code >= 300:
        return response.status_code

    headers = response.headers
    body = response.json()

    return {'headers': headers, 'body': body}


def extract_info(data) -> (dict[str, object]):
    return {
        'Date': data['headers']['Date'],
        'Domain': data['body']['domain'],
        'Groups': data['body']['groups']
    }
