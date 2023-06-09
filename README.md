# OSINT-OCTOPUS

OSINT-octopus is a collection of different OSINT tools brought together in a python GUI application. Feature include:
 - checking if an email was in a data breach with breachdirectory
 - use builtWith to determine what technologies a website uses 
 - use zoomEye to see vulnerable, open devices connected to the internet
 - harvest POC data from whois queries for a given domain using recon-ng's whois_pocs module
 - find emails and subdomains for a given domain using theHarvester
 - run an Nmap scan to discover ports, services, os's
 - run metagoofil to find and download documents belonging to a target
 - use PyExifTool to extract metadata from files
 - check files for malware using VirusTotal

## SETUP & INSTALLATION

This software was tested on Kali GNU/Linux version 2023.1

1. Ensure that the following are installed:
    - [python v3.11.2](https://linuxnightly.com/install-python-kali-linux/)
    - pip v23.0.1
    - [recon-cli v5.1.2](https://www.kali.org/tools/recon-ng/)
      - [recon/domains-contacts/whois_pocs module](https://www.101labs.net/comptia-security/lab-3-recon-ng/)
    - [theHarvester v4.2.0](https://www.kali.org/tools/theharvester/)
    -[metagoofil v1.2.0](https://www.kali.org/tools/metagoofil/)
2. Place API keys in `.env` file in the root of the project (you can rename 'env_template.txt)
    - [breachdirectry](https://rapidapi.com/rohan-patra/api/breachdirectory) : XRAPID_API_KEY
    - [BuiltWith](https://api.builtwith.com/free-api) : BUILTWITH_API_KEY
    - [ZoomEye](https://www.zoomeye.org/doc) : ZOOMEYE_API_KEY
    - [VirusTotal](https://developers.virustotal.com/reference/overview) : VIRUSTOTAL_API_KEY
3. Run command `pip install -r requirements.txt`
4. To start the app run `python osint_octopus.py`

To run tests run `python run_tests.py`

## USAGE

#### Check Email

To check is an email has been in a breach input an email address and click `Check Email`. The Response windows are scrollable.

![Check Email](./images/CHECK_EMAIL.png)

#### Save Response

To save a response input a file name into the 'Save response' box and click `Save` and select where to save it.

![Save](images/save.png)

#### Check Domain

To determine what technologies are used input a domain name and click `Check Domain`

![Check Domain](images/CHECK_DOMAIN.png)

#### ZoomEye

To use ZoomEye select a type and input a value corresponding to a type. [More info](https://www.zoomeye.org/doc)

![Search filters](images/search_filter.png)

![ZoomEye](images/ZoomEye.png)

#### Recon-ng

To use the recon-ng whois_poc module input a domain name.

![RECON](images/recon-ng.png)

#### theHarvester

To use theHarvester input a domain, select a source and input a limit on the number of results.

![theHarvester](images/theHarvester.png)

#### Nmap

To run an Nmap scan input a host or ip address.
The default values for the other fields are:

- Ports : '1-1000'
- Arguments : '-A'
- Timeout : 0

![Nmap](images/nmap.png)

#### Check File

To check is a file is malicious input it's path, relative paths are based the projects root.

![Check File](images/CHECK_FILE.png)

#### Metagoofil

To use Metagoofil input a domain and a file type.
The defaults for the other fields are:

- Delay : 30
- Search max : 100
- Download file limit : 100
- Save directory : '.'
- Number of threads : 8
- URL timeout : 15
- User agent : None
- Save file name : None
- Download : False

![metagoofil](images/metagoofil.png)

#### Extract Metadata

To extract metadata from a file input the file path or a comma separated list of files.

![metadata](images/metadata.png)


# Documentation

### Tools and APIS used

- https://breachdirectory.org/
- https://pro.builtwith.com/
- https://www.zoomeye.org/
- https://github.com/lanmaster53/recon-ng
- https://github.com/laramies/theHarvester
- https://nmap.org/
- https://github.com/opsdisk/metagoofil
- https://pypi.org/project/PyExifTool/
- https://www.virustotal.com/gui/home/upload

## System Overview

#### osint_octopus.py

This is the entrypoint to the app and the code for the tkinter GUI is also located in this file. 

Each function corresponds to a number to interact with tkinter widgets:

1. checkEmail
2. builtWith
3. zoomEye
4. recon_ng
5. theHarvester
6. run_nmap
7. checkFile
8. metagoofil
9. extractMetadata

#### run_tests.py

*Note: I couldn't get pytest to run because of some of the imported libraries interfered with it*

Calls the tests module.

### Modules

#### tests.py

Checks to make sure the extract_info functions work, make sure that invalid file paths are not sent to VirusTotal. The extractMetadata function is tested. Access to the recon-cli and metagoofil is tested.

#### breachdirectory.py

- **checkEmail**: Takes a user input email and calls the function *apiRequest*. Will return 'Rate Limit Reached' if the response if code is 429 or just the response or the extracted from the response.
- **apiRequest**: Input is an email, make the api request, if the response code isn't in the 200's return the code, otherwise return the headers and body of the response as a dict.
- **extractInfo**: Input is the return of *apiRequest* and returns a dict containing the date, requests remaining, the number of results and the results.

#### builtwith.py

- **builtWith**: Takes a user input domain and calls the function *apiRequest*. Will return 'Rate Limit Reached' if the response if code is 429 or just the response or the extracted from the response.
- **apiRequest**: Input is an email, make the api request, if the response code isn't in the 200's return the code, otherwise return the headers and body of the response as a dict.
- **extractInfo**: Input is the return of *apiRequest* and returns a dict containing the date, domain and the groups.

#### exiftool.py

- **exiftool**: Takes in a comma separated list of files from the user. Return the metadata of the file, and any invalid files in a dict.

#### metagoofil.py

- **meatagoofil**: requires a user input domain and file type. Uses subprocess to run a command that an array and return the captured output.

Defaults for the rest of the values are:
- delay: float = 30.0,
- search_max: int = 100,
- download_file_limit: int = 100,
- save_directory: str = '.',
- number_of_threads: int = 8,
- url_timeout: int = 15,
- user_agent: Optional[str] = None,
- save_file: Optional[str] = None,
- download: bool = False

#### nmap.py

- **run_nmap**: Run an nmap scan using the nmap library and return a string.

Defaults for the inputs are:
- hosts: str = '127.0.0.1',
- ports: str | None = None,
- arguments: str = '-A',
- timeout: int = 0

#### recon_ng.py

- **recon_ng**: Input is a user supplied domain, and uses subprocess to run a command from a list, returns the captured output.

#### theHarvester.py

- **theHarvester**: takes in a user input domain and limit, sources is selected from a list. Uses subprocess to run a command from a list, returns the captured output.

The options for source are:
'anubis', 'baidu', 'bevigil', 'binaryedge', 'bing', 'bingapi',
'bufferoverun', 'censys', 'certspotter', 'crtsh',
'dnsdumpster', 'duckduckgo', 'fullhunt',
'github-code', 'hackertarget', 'hunter',
'intelx', 'omnisint', 'otx', 'pentesttools',
'projectdiscovery', 'qwant', 'rapiddns',
'rocketreach', 'securityTrails', 'sublist3r',
'threatcrowd', 'threatminer',
'urlscan', 'virustotal', 'yahoo', 'zoomeye'

#### virustotal.py

- **checkFiles**: takes an user input file path, returns a the following dict if invalid file path `{'Error': 'Invalid file path'}`. Otherwise passes the path to the VirusTotal client to check the file. Returns a dict with date, stats, and results based on the response from the vt client.

#### zoomeye.py

- **zoomEye**: Input is a user selected filter and user input name. Calls apiRequest with those and returns the extracted info, or if the request failed the corresponding error message.
- **apiRequest**: Input is a user selected filter and user input name. Makes the api request, and if successful will return the headers and body, others the failing response code.
- **extract_info**: Input the return of apiRequest if it was successful, and returns the date and body.

Filter types: 'app', 'device', 'os', 'service', 'ip', 'cidr','hostname', 'port', 'city', 'country', 'asn','header', 'title', 'site'

If the response code does not match one of the following just the number is returned:
- 400: "request invalid, validate usage and try again",
- 401: "request not authenticated, API token is missing, invalid or expired",
- 402: "credits of the account was insufficient",
- 403: "request not authorized, credential was suspended, exceeded usage",
- 404: "request failed, the specified resource does not exist",
- 405: "request failed, the specified method was not allowed",
- 500: "error occurred, we are notified",
- 503: "the request source was not available"