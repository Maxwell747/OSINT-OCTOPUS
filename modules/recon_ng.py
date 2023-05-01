import subprocess


def recon_ng(domain: str) -> str:

    command = ['recon-cli',
               '-w',
               'whois_recon',
               '-m',
               'recon/domains-contacts/whois_pocs',
               '-o',
               'source={domain}'.format(domain=domain),
               '-x']

    result = subprocess.run(
        command, capture_output=True, text=True, shell=False)

    return result.stdout
