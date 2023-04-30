from dotenv import dotenv_values
import vt

client = vt.Client(dotenv_values('.env')['VIRUSTOTAL_API_KEY'])


def checkFile(path: str):
    with open(path, 'rb') as f:
        analysis = client.scan_file(f, wait_for_completion=True)

    return {'Date': analysis.date,
            'Results': analysis.results,
            'Stats': analysis.stats}
