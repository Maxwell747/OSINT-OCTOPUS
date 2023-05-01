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

    cmd = ['theHarvester',
           '-d {}'.format(domain),
           '-b {}'.format(source),
           '-l {}'.format(limit)
           ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, shell=False)

    return result.stdout
