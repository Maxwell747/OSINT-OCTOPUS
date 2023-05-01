import subprocess
from typing import Literal

Source = Literal['anubis', 'baidu', 'bevigil', 'binaryedge', 'bing', 'bingapi',
                 'bufferoverun', 'censys', 'certspotter', 'crtsh',
                 'dnsdumpster', 'duckduckgo', 'fullhunt',
                 'github-code', 'hackertarget', 'hunter',
                 'intelx', 'omnisint', 'otx', 'pentesttools',
                 'projectdiscovery', 'qwant', 'rapiddns',
                 'rocketreach', 'securityTrails', 'sublist3r',
                 'threatcrowd', 'threatminer',
                 'urlscan', 'virustotal', 'yahoo', 'zoomeye']


def theHarvester(domain: str, source: Source, limit: int) -> str:

    command = ['theHarvester',
               '-d {domain}'.format(domain=domain),
               '-b {source}'.format(source=source),
               '-l {limit}'.format(limit=limit)
               ]

    result = subprocess.run(
        command, capture_output=True, text=True, shell=False)

    return result.stdout
