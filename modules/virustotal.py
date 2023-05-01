from dotenv import dotenv_values
import vt
import os

client = vt.Client(dotenv_values('.env')['VIRUSTOTAL_API_KEY'])


def checkFile(path: str) -> dict:
    if not os.path.isfile(path):
        return {'Error': 'Invalid file path'}

    with open(path, 'rb') as f:
        analysis = client.scan_file(f, wait_for_completion=True)

    return {'Date': analysis.date,
            'Stats': analysis.stats,
            'Results': analysis.results
            }
