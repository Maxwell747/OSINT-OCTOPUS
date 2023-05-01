import subprocess


def recon_ng(domain: str) -> str:

    cmd = ['recon-cli',
           '-w',
           'whois_recon',
           '-m',
           'recon/domains-contacts/whois_pocs',
           '-o',
           'source={}'.format(domain),
           '-x']

    result = subprocess.run(
        cmd, capture_output=True, text=True, shell=False)

    return result.stdout
