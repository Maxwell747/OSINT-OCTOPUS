import subprocess
from typing import Optional


def metagoofil(domain: str,
               file_types: str,
               delay: float = 30.0,
               search_max: int = 100,
               download_file_limit: int = 100,
               save_directory: str = '.',
               number_of_threads: int = 8,
               url_timeout: int = 15,
               user_agent: Optional[str] = None,
               save_file: Optional[str] = None,
               download: bool = False) -> str:

    cmd = ['metagoofil',
           '-d {}'.format(domain),
           '-t {}'.format(file_types),
           '-e {}'.format(delay),
           '-l {}'.format(search_max),
           '-n {}'.format(download_file_limit),
           '-o {}'.format(save_directory),
           '-r {}'.format(number_of_threads),
           '-i {}'.format(url_timeout)]

    if user_agent is not None:
        cmd.append('-u {}'.format(user_agent))
    if save_file is not None:
        cmd.append('-f {}'.format(save_file))
    if download:
        cmd.append('-w')

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout
