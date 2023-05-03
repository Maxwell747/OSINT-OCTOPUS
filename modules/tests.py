# NOTE: I tried using pytest,
# but some of libraries used crashed pytest for reasons I am not sure of

from ast import literal_eval
from .breachdirectory import extract_info as testEmail
from .builtwith import extract_info as testDomain
from .virustotal import checkFile
from .exiftool import extractMetadata

import subprocess

# to my knowledge literal_eval is safe
# it never executes the string passed to it


def run_tests():
    result_1 = breachdirectory_tests()
    result_2 = builtwith_tests()
    result_3 = recon_ng_tests()
    result_4 = checkFile_tests()
    result_5 = metagoofil_tests()
    result_6 = extractMetadata_tests()
    return {
        'breachdirectory_tests': result_1,
        'builtwith_tests': result_2,
        'recon_ng_tests': result_3,
        'checkFile_tests': result_4,
        'metagoofil_tests': result_5,
        'exiftool_tests': result_6
    }


def breachdirectory_tests():
    with open('./mock/testEmail_input.txt') as inputFile:
        input = literal_eval(inputFile.read())
    with open('./mock/testEmail_output.txt') as outputFile:
        expected_output = literal_eval(outputFile.read())

    return 'PASSED' if testEmail(input) == expected_output else 'FAILED'


def builtwith_tests():
    with open('./mock/testDomain_input.txt') as inputFile:
        input = literal_eval(inputFile.read())
    with open('./mock/testDomain_output.txt') as outputFile:
        expected_output = literal_eval(outputFile.read())

    return 'PASSED' if testDomain(input) == expected_output else 'FAILED'


def recon_ng_tests():
    cmd = ['recon-cli', '--version']

    result = subprocess.run(
        cmd, capture_output=True, text=True, shell=False)

    return 'PASSED' if result.stdout == '5.1.2\n' else\
        f'FAILED: Expected 5.1.2 - Actual: {result.stdout}'


def checkFile_tests():
    expected = {'Error': 'Invalid file path'}
    actual = checkFile('not a file path')

    return 'PASSED' if checkFile('oasidfn') == expected else\
        f'FAILED: Expected {expected} - Actual {actual}'


def metagoofil_tests():
    expected = 'usage: metagoofil.py [-h] -d DOMAIN [-e DELAY] [-f [SAVE_FILE]]\n                     [-i URL_TIMEOUT] [-l SEARCH_MAX] [-n DOWNLOAD_FILE_LIMIT]\n                     [-o SAVE_DIRECTORY] [-r NUMBER_OF_THREADS] -t FILE_TYPES\n                     [-u [USER_AGENT]] [-w]\nmetagoofil.py: error: the following arguments are required: -d, -t\n'

    cmd = ['metagoofil', '-v']

    result = subprocess.run(
        cmd, capture_output=True, text=True, shell=False)

    return 'PASSED' if result.stderr == expected else\
        f'FAILED: Expected {expected} - Actual: {result}'


def extractMetadata_tests():
    valid_file = ['run_tests.py']
    invalid_file = ['jkashf']
    both_files = ['./run_tests.py', 'asdfasdf']
    no_files = []

    case_1 = 'metadata' in extractMetadata(valid_file).keys()

    case_2 = extractMetadata(invalid_file) == {'Invalid Files': ['jkashf']}

    case_3 = 'metadata' in extractMetadata(both_files).keys() and \
        extractMetadata(both_files)['Invalid Files'] == ['asdfasdf']

    case_4 = extractMetadata(no_files) == {'Invalid Files': []}

    failed_cases = []

    if not case_1:
        failed_cases.append('case 1')
    if not case_2:
        failed_cases.append('case 2')
    if not case_3:
        failed_cases.append('case 3')
    if not case_4:
        failed_cases.append('case 4')

    if failed_cases:
        return f'FAILED: {failed_cases}'
    else:
        return 'PASSED'
