from modules import (checkEmail, builtWith, zoomEye, recon_ng,
                     theHarvester, run_nmap, checkFile, metagoofil,
                     extractMetadata)
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog

root = tk.Tk()
root.geometry('1000x900')
root.title('OSINT Octopus')

notebook = ttk.Notebook(root)


def check_email_address():
    email = entry_email1.get()
    if not email:
        text_response1.insert('end', 'Please enter an email address.\n')
    else:
        response = checkEmail(email)
        if response == 'Rate Limit Reached':
            text_response1.insert(
                'end', 'Rate Limit Reached. Please try again later.\n')
        else:
            text_response1.insert('end', f'{response}\n')


def check_domain():
    domain = entry_domain2.get()
    if not domain:
        text_response2.insert('end', 'Please enter a domain name.\n')
    else:
        response = builtWith(domain)
        if response == {}:
            text_response2.insert(
                'end', 'No technology information found for this domain.\n')
        elif isinstance(response, dict):
            for key, value in response.items():
                text_response2.insert('end', f'{key}: {value}\n')
        elif isinstance(response, int):
            text_response2.insert(
                'end', 'Rate Limit Reached. Please try again later.\n')


def zoom_eye():
    filter_type = filter_var3.get()
    name = entry_name3.get()
    if not name:
        text_response3.insert('end', 'Please enter a name.\n')
    else:
        response = zoomEye(filter_type, name)  # type: ignore
        if response == 'Rate Limit Reached':
            text_response3.insert(
                'end', 'Rate Limit Reached. Please try again later.\n')
        else:
            text_response3.insert('end', f'{response}\n')


def run_recon_ng():
    domain = entry_domain4.get()
    if not domain:
        text_response4.insert('end', 'Please enter a domain name.\n')
    else:
        response = recon_ng(domain)
        text_response4.insert('end', f'{response}\n')


def run_theHarvester():
    domain = entry_domain5.get()
    source = source_var5.get()
    limit = entry_limit5.get()
    if not domain or not limit or not limit:
        text_response5.insert(
            'end', 'Please enter a domain, source and a limit.\n')
    else:
        response = theHarvester(domain, source, limit)  # type: ignore
        text_response5.delete('1.0', 'end')
        text_response5.insert('end', f'{response}\n')


def run_nmap_scan():
    hosts = entry_hosts6.get()
    ports = entry_ports6.get() or '1-1000'
    arguments = entry_arguments6.get() or '-A'
    timeout = entry_timeout6.get() or 0

    if not hosts:
        text_response6.insert('end', 'Please enter a host or IP address.\n')
    else:
        response = run_nmap(hosts, ports, arguments, int(timeout))
        text_response6.insert('end', f'{response}\n')


def check_file():
    path = entry_path7.get()
    if not path:
        text_response7.insert('end', 'Please enter a file path.\n')
    else:
        response = checkFile(path)
        text_response7.delete('1.0', tk.END)
        for key, value in response.items():
            text_response7.insert('end', f'{key}: {value}\n')


def run_metagoofil():
    domain = entry_domain8.get()
    file_types = entry_filetypes8.get()
    delay = entry_delay8.get() or 30
    search_max = entry_searchmax8.get() or 100
    download_file_limit = entry_downloadfilelimit8.get() or 100
    save_directory = entry_savedirectory8.get() or '.'
    number_of_threads = entry_numthreads8.get() or 8
    url_timeout = entry_urltimeout8.get() or 15
    user_agent = entry_useragent8.get() or None
    save_file = entry_savefile8.get() or None
    download = download_file_var.get() or False

    if not domain or not file_types:
        text_response8.insert('end', 'Please enter a domain and file types.\n')
        return

    response = metagoofil(
        domain=domain,
        file_types=file_types,
        delay=int(delay),
        search_max=int(search_max),
        download_file_limit=int(download_file_limit),
        save_directory=save_directory,
        number_of_threads=int(number_of_threads),
        url_timeout=int(url_timeout),
        user_agent=user_agent,
        save_file=save_file,
        download=bool(download)
    )

    text_response8.insert('end', f'{response}\n')


def extract_metadata():
    files = entry_files9.get()
    if not files:
        text_response9.insert(
            'end', 'Please enter a comma-separated list of files.\n')
    else:
        files = [file.strip() for file in files.split(',')]
        response = extractMetadata(files)
        text_response9.insert('end', f'{response}\n')


def save_response9():
    response = text_response9.get('1.0', 'end-1c')
    filename = entry_save9.get()
    if not filename:
        text_response9.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response9.insert('end', f'Response saved to {filepath}\n')


def save_response1():
    response = text_response1.get('1.0', 'end-1c')
    filename = entry_save1.get()
    if not filename:
        text_response1.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response1.insert('end', f'Response saved to {filepath}\n')


def save_response2():
    response = text_response2.get('1.0', 'end-1c')
    filename = entry_save2.get()
    if not filename:
        text_response2.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response2.insert('end', f'Response saved to {filepath}\n')


def save_response3():
    response = text_response3.get('1.0', 'end-1c')
    filename = entry_save3.get()
    if not filename:
        text_response3.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response3.insert('end', f'Response saved to {filepath}\n')


def save_response4():
    response = text_response4.get('1.0', 'end-1c')
    filename = entry_save4.get()
    if not filename:
        text_response4.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response4.insert('end', f'Response saved to {filepath}\n')


def save_response5():
    response = text_response5.get('1.0', 'end-1c')
    filename = entry_save5.get()
    if not filename:
        text_response5.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response5.insert('end', f'Response saved to {filepath}\n')


def save_response6():
    response = text_response6.get('1.0', 'end-1c')
    filename = entry_save6.get()
    if not filename:
        text_response6.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response6.insert('end', f'Response saved to {filepath}\n')


def save_response7():
    response = text_response7.get('1.0', 'end-1c')
    filename = entry_save7.get()
    if not filename:
        text_response7.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response7.insert('end', f'Response saved to {filepath}\n')


def save_response8():
    response = text_response8.get('1.0', 'end-1c')
    filename = entry_save8.get()
    if not filename:
        text_response8.insert('end', 'Please enter a filename.\n')
    else:
        filetypes = [('Text Files', '*.txt'), ('All Files', '*.*')]
        filepath = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=filetypes, initialfile=filename)
        with open(filepath, 'w') as f:
            f.write(response)
        text_response8.insert('end', f'Response saved to {filepath}\n')


# 1 - Create a frame for the email checker
frame_check_email = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the email address
label_email1 = ttk.Label(frame_check_email, text='Email address:')
label_email1.grid(column=0, row=0, sticky='w')
entry_email1 = ttk.Entry(frame_check_email, width=40)
entry_email1.grid(column=1, row=0, sticky='w')

# Create a Button widget for checking the email
button_check_email1 = ttk.Button(
    frame_check_email, text='Check Email', command=check_email_address)
button_check_email1.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response1 = ttk.Label(frame_check_email, text='Response:')
label_response1.grid(column=0, row=1, sticky='w')
text_response1 = tk.Text(frame_check_email, height=40)
text_response1.grid(column=1, row=1, columnspan=2, sticky='w')

# Create a Button widget for saving the response
label_save1 = ttk.Label(frame_check_email, text='Save response:')
label_save1.grid(column=0, row=2, sticky='w')
entry_save1 = ttk.Entry(frame_check_email, width=40)
entry_save1.grid(column=1, row=2, sticky='w')
button_save1 = ttk.Button(
    frame_check_email, text='Save', command=save_response1)
button_save1.grid(column=2, row=2, sticky='w')

notebook.add(frame_check_email, text='Check Email')

# 2 - Create a frame for the domain checker
frame_check_domain = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the domain name
label_domain2 = ttk.Label(frame_check_domain, text='Domain name:')
label_domain2.grid(column=0, row=0, sticky='w')
entry_domain2 = ttk.Entry(frame_check_domain, width=40)
entry_domain2.grid(column=1, row=0, sticky='w')

# Create a Button widget for checking the domain
button_check_domain2 = ttk.Button(
    frame_check_domain, text='Check Domain', command=check_domain)
button_check_domain2.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response2 = ttk.Label(frame_check_domain, text='Response:')
label_response2.grid(column=0, row=1, sticky='w')
text_response2 = tk.Text(frame_check_domain, height=40)
text_response2.grid(column=1, row=1, columnspan=2, sticky='w')

# Create a Button widget for saving the response
label_save2 = ttk.Label(frame_check_domain, text='Save response:')
label_save2.grid(column=0, row=2, sticky='w')
entry_save2 = ttk.Entry(frame_check_domain, width=40)
entry_save2.grid(column=1, row=2, sticky='w')
button_save2 = ttk.Button(
    frame_check_domain, text='Save', command=save_response2)
button_save2.grid(column=2, row=2, sticky='w')

notebook.add(frame_check_domain, text='Check Domain')

# 3 - Create a frame for the ZoomEye search
frame_zoom_eye = ttk.Frame(notebook, padding=20)

# Create a dropdown menu for selecting the filter type
label_filter3 = ttk.Label(frame_zoom_eye, text='Type:')
label_filter3.grid(column=0, row=0, sticky='w')
filter_var3 = tk.StringVar()
filter_dropdown3 = ttk.Combobox(frame_zoom_eye, width=20,
                                textvariable=filter_var3, values=[
                                    'app', 'device', 'os', 'service', 'ip',
                                    'cidr', 'hostname',
                                    'port', 'city', 'country', 'asn',
                                    'header', 'title', 'site'])
filter_dropdown3.grid(column=1, row=0, sticky='w')

# Create an Entry widget for the name
label_name3 = ttk.Label(frame_zoom_eye, text='Value:')
label_name3.grid(column=0, row=1, sticky='w')
entry_name3 = ttk.Entry(frame_zoom_eye, width=40)
entry_name3.grid(column=1, row=1, sticky='w')

# Create a Button widget for searching ZoomEye
button_zoom_eye3 = ttk.Button(
    frame_zoom_eye, text='Search', command=zoom_eye)
button_zoom_eye3.grid(column=2, row=1, sticky='w')

# Create a Text widget for displaying the response
label_response3 = ttk.Label(frame_zoom_eye, text='Response:')
label_response3.grid(column=0, row=2, sticky='w')
text_response3 = tk.Text(frame_zoom_eye, height=40)
text_response3.grid(column=1, row=2, columnspan=2, sticky='w')

# Create a Button widget for saving the response
label_save3 = ttk.Label(frame_zoom_eye, text='Save response:')
label_save3.grid(column=0, row=3, sticky='w')
entry_save3 = ttk.Entry(frame_zoom_eye, width=40)
entry_save3.grid(column=1, row=3, sticky='w')
button_save3 = ttk.Button(frame_zoom_eye, text='Save', command=save_response3)
button_save3.grid(column=2, row=3, sticky='w')

notebook.add(frame_zoom_eye, text='ZoomEye')

# 4 - Create a frame for the recon-ng function
frame_recon_ng = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the domain name
label_domain4 = ttk.Label(frame_recon_ng, text='Domain name:')
label_domain4.grid(column=0, row=0, sticky='w')
entry_domain4 = ttk.Entry(frame_recon_ng, width=40)
entry_domain4.grid(column=1, row=0, sticky='w')

# Create a Button widget for running the recon-ng function
button_run4 = ttk.Button(frame_recon_ng, text='Run', command=run_recon_ng)
button_run4.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response4 = ttk.Label(frame_recon_ng, text='Response:')
label_response4.grid(column=0, row=1, sticky='w')
text_response4 = tk.Text(frame_recon_ng, height=40)
text_response4.grid(column=1, row=1, columnspan=2, sticky='w')

# Create a Button widget for saving the response
label_save4 = ttk.Label(frame_recon_ng, text='Save response:')
label_save4.grid(column=0, row=2, sticky='w')
entry_save4 = ttk.Entry(frame_recon_ng, width=40)
entry_save4.grid(column=1, row=2, sticky='w')
button_save4 = ttk.Button(frame_recon_ng, text='Save', command=save_response4)
button_save4.grid(column=2, row=2, sticky='w')

notebook.add(frame_recon_ng, text='recon-ng')

# 5 - Create a frame for the theHarvester
frame_theHarvester = ttk.Frame(notebook, padding=20)

# Create a Label widget for the domain
label_domain5 = ttk.Label(frame_theHarvester, text='Domain:')
label_domain5.grid(column=0, row=0, sticky='w')
entry_domain5 = ttk.Entry(frame_theHarvester, width=40)
entry_domain5.grid(column=1, row=0, sticky='w')

# Create a dropdown list for the source
label_source5 = ttk.Label(frame_theHarvester, text='Source:')
label_source5.grid(column=0, row=1, sticky='w')
sources5 = ['anubis', 'baidu', 'bevigil', 'binaryedge', 'bing', 'bingapi',
            'bufferoverun', 'censys', 'certspotter', 'crtsh',
            'dnsdumpster', 'duckduckgo', 'fullhunt',
            'github-code', 'hackertarget', 'hunter',
            'intelx', 'omnisint', 'otx', 'pentesttools',
            'projectdiscovery', 'qwant', 'rapiddns',
            'rocketreach', 'securityTrails', 'sublist3r',
            'threatcrowd', 'threatminer',
            'urlscan', 'virustotal', 'yahoo', 'zoomeye']
source_var5 = tk.StringVar(frame_theHarvester)
source_var5.set(sources5[0])
dropdown_source5 = ttk.OptionMenu(frame_theHarvester, source_var5, *sources5)
dropdown_source5.grid(column=1, row=1, sticky='w')

# Create a Label widget for the limit
label_limit5 = ttk.Label(frame_theHarvester, text='Limit:')
label_limit5.grid(column=0, row=2, sticky='w')
entry_limit5 = ttk.Entry(frame_theHarvester, width=40)
entry_limit5.grid(column=1, row=2, sticky='w')

# Create a Button widget for running theHarvester
button_run5 = ttk.Button(frame_theHarvester, text='Run',
                         command=run_theHarvester)
button_run5.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response5 = ttk.Label(frame_theHarvester, text='Response:')
label_response5.grid(column=0, row=3, sticky='w')
text_response5 = tk.Text(frame_theHarvester, height=35)
text_response5.grid(column=1, row=3, columnspan=2, sticky='w')

# Create a Label widget for saving the response
label_save5 = ttk.Label(frame_theHarvester, text='Save response:')
label_save5.grid(column=0, row=4, sticky='w')
entry_save5 = ttk.Entry(frame_theHarvester, width=40)
entry_save5.grid(column=1, row=4, sticky='w')
button_save5 = ttk.Button(
    frame_theHarvester, text='Save', command=save_response5)
button_save5.grid(column=2, row=4, sticky='w')

notebook.add(frame_theHarvester, text='theHarvester')

# 6 - Create a frame for the nmap scanner
frame_nmap_scan = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the hosts
label_hosts6 = ttk.Label(frame_nmap_scan, text='Hosts:')
label_hosts6.grid(column=0, row=0, sticky='w')
entry_hosts6 = ttk.Entry(frame_nmap_scan, width=40)
entry_hosts6.grid(column=1, row=0, sticky='w')

# Create an Entry widget for the ports
label_ports6 = ttk.Label(frame_nmap_scan, text='Ports:')
label_ports6.grid(column=0, row=1, sticky='w')
entry_ports6 = ttk.Entry(frame_nmap_scan, width=40)
entry_ports6.grid(column=1, row=1, sticky='w')

# Create an Entry widget for the arguments
label_arguments6 = ttk.Label(frame_nmap_scan, text='Arguments:')
label_arguments6.grid(column=0, row=2, sticky='w')
entry_arguments6 = ttk.Entry(frame_nmap_scan, width=40)
entry_arguments6.grid(column=1, row=2, sticky='w')

# Create an Entry widget for the timeout
label_timeout6 = ttk.Label(frame_nmap_scan, text='Timeout:')
label_timeout6.grid(column=0, row=3, sticky='w')
entry_timeout6 = ttk.Entry(frame_nmap_scan, width=40)
entry_timeout6.grid(column=1, row=3, sticky='w')

# Create a Button widget for running the scan
button_run6 = ttk.Button(frame_nmap_scan, text='Run',
                         command=run_nmap_scan)
button_run6.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response6 = ttk.Label(frame_nmap_scan, text='Response:')
label_response6.grid(column=0, row=4, sticky='w')
text_response6 = tk.Text(frame_nmap_scan, height=35)
text_response6.grid(column=1, row=4, columnspan=2, sticky='w')

# Create a Label widget for saving the response
label_save6 = ttk.Label(frame_nmap_scan, text='Save response:')
label_save6.grid(column=0, row=5, sticky='w')
entry_save6 = ttk.Entry(frame_nmap_scan, width=40)
entry_save6.grid(column=1, row=5, sticky='w')
button_save6 = ttk.Button(
    frame_nmap_scan, text='Save', command=save_response6)
button_save6.grid(column=2, row=5, sticky='w')

notebook.add(frame_nmap_scan, text='nmap')

# 7 - Create a frame for the file checker
frame_check_file = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the file path
label_path7 = ttk.Label(frame_check_file, text='File path:')
label_path7.grid(column=0, row=0, sticky='w')
entry_path7 = ttk.Entry(frame_check_file, width=40)
entry_path7.grid(column=1, row=0, sticky='w')

# Create a Button widget for checking the file
button_check_file7 = ttk.Button(
    frame_check_file, text='Check File', command=check_file)
button_check_file7.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response7 = ttk.Label(frame_check_file, text='Response:')
label_response7.grid(column=0, row=1, sticky='w')
text_response7 = tk.Text(frame_check_file, height=40)
text_response7.grid(column=1, row=1, columnspan=2, sticky='w')

# Create a Button widget for saving the response
label_save7 = ttk.Label(frame_check_file, text='Save response:')
label_save7.grid(column=0, row=2, sticky='w')
entry_save7 = ttk.Entry(frame_check_file, width=40)
entry_save7.grid(column=1, row=2, sticky='w')
button_save7 = ttk.Button(
    frame_check_file, text='Save', command=save_response7)
button_save7.grid(column=2, row=2, sticky='w')

notebook.add(frame_check_file, text='Check File')

# 8 - Create a frame for the Metagoofil runner
frame_metagoofil = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the domain
label_domain8 = ttk.Label(frame_metagoofil, text='Domain(required):')
label_domain8.grid(column=0, row=0, sticky='w')
entry_domain8 = ttk.Entry(frame_metagoofil, width=40)
entry_domain8.grid(column=1, row=0, sticky='w')

# Create an Entry widget for the file types
label_filetypes8 = ttk.Label(frame_metagoofil, text='File types(required):')
label_filetypes8.grid(column=0, row=1, sticky='w')
entry_filetypes8 = ttk.Entry(frame_metagoofil, width=40)
entry_filetypes8.grid(column=1, row=1, sticky='w')

# Create an Entry widget for the delay
label_delay8 = ttk.Label(frame_metagoofil, text='Delay:')
label_delay8.grid(column=0, row=2, sticky='w')
entry_delay8 = ttk.Entry(frame_metagoofil, width=40)
entry_delay8.grid(column=1, row=2, sticky='w')

# Create an Entry widget for the search max
label_searchmax8 = ttk.Label(frame_metagoofil, text='Search max:')
label_searchmax8.grid(column=0, row=3, sticky='w')
entry_searchmax8 = ttk.Entry(frame_metagoofil, width=40)
entry_searchmax8.grid(column=1, row=3, sticky='w')

# Create an Entry widget for the download file limit
label_downloadfilelimit8 = ttk.Label(
    frame_metagoofil, text='Download file limit:')
label_downloadfilelimit8.grid(column=0, row=4, sticky='w')
entry_downloadfilelimit8 = ttk.Entry(frame_metagoofil, width=40)
entry_downloadfilelimit8.grid(column=1, row=4, sticky='w')

# Create an Entry widget for the save directory
label_savedirectory8 = ttk.Label(frame_metagoofil, text='Save directory:')
label_savedirectory8.grid(column=0, row=5, sticky='w')
entry_savedirectory8 = ttk.Entry(frame_metagoofil, width=40)
entry_savedirectory8.grid(column=1, row=5, sticky='w')

# Create an Entry widget for the number of threads
label_numthreads8 = ttk.Label(frame_metagoofil, text='Number of threads:')
label_numthreads8.grid(column=0, row=6, sticky='w')
entry_numthreads8 = ttk.Entry(frame_metagoofil, width=40)
entry_numthreads8.grid(column=1, row=6, sticky='w')

# Create an Entry widget for the URL timeout
label_urltimeout8 = ttk.Label(frame_metagoofil, text='URL timeout:')
label_urltimeout8.grid(column=0, row=7, sticky='w')
entry_urltimeout8 = ttk.Entry(frame_metagoofil, width=40)
entry_urltimeout8.grid(column=1, row=7, sticky='w')

# Create an Entry widget for the user agent
label_useragent8 = ttk.Label(frame_metagoofil, text='User agent:')
label_useragent8.grid(column=0, row=8, sticky='w')
entry_useragent8 = ttk.Entry(frame_metagoofil, width=40)
entry_useragent8.grid(column=1, row=8, sticky='w')

# Create an Entry widget for the save file
label_savefile8 = ttk.Label(frame_metagoofil, text='Save file name:')
label_savefile8.grid(column=0, row=9, sticky='w')
entry_savefile8 = ttk.Entry(frame_metagoofil, width=40)
entry_savefile8.grid(column=1, row=9, sticky='w')

# Create a Checkbutton widget for the download
label_download8 = ttk.Label(frame_metagoofil, text='Download:')
label_download8.grid(column=0, row=10, sticky='w')
download_file_var = tk.BooleanVar()
download8 = ttk.Checkbutton(frame_metagoofil, variable=download_file_var)
download8.grid(column=1, row=10, sticky='w')

# Create a Button widget to start scan
button_check_domain8 = ttk.Button(
    frame_metagoofil, text='Scan for files', command=run_metagoofil)
button_check_domain8.grid(column=2, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response8 = ttk.Label(frame_metagoofil, text='Response:')
label_response8.grid(column=0, row=11, sticky='w')
text_response8 = tk.Text(frame_metagoofil, height=30)
text_response8.grid(column=1, row=11, columnspan=2, sticky='w')

# Create a Button widget for saving the response
label_save8 = ttk.Label(frame_metagoofil, text='Save response:')
label_save8.grid(column=0, row=12, sticky='w')
entry_save8 = ttk.Entry(frame_metagoofil, width=40)
entry_save8.grid(column=1, row=12, sticky='w')
button_save8 = ttk.Button(
    frame_metagoofil, text='Save', command=save_response8)
button_save8.grid(column=2, row=12, sticky='w')

notebook.add(frame_metagoofil, text='metagoofil')

# 9 - Create a frame for the metadata extractor
frame_extract_metadata = ttk.Frame(notebook, padding=20)

# Create an Entry widget for the list of files
label_files9 = ttk.Label(frame_extract_metadata, text='Files:')
label_files9.grid(column=0, row=0, sticky='w')
entry_files9 = ttk.Entry(frame_extract_metadata, width=80)
entry_files9.grid(column=1, row=0, columnspan=2, sticky='w')

# Create a Button widget for extracting the metadata
button_extract_metadata9 = ttk.Button(
    frame_extract_metadata, text='Extract Metadata', command=extract_metadata)
button_extract_metadata9.grid(column=3, row=0, sticky='w')

# Create a Text widget for displaying the response
label_response9 = ttk.Label(frame_extract_metadata, text='Response:')
label_response9.grid(column=0, row=1, sticky='w')
text_response9 = tk.Text(frame_extract_metadata, height=40)
text_response9.grid(column=1, row=1, columnspan=3, sticky='w')

# Create a Button widget for saving the response
label_save9 = ttk.Label(frame_extract_metadata, text='Save response:')
label_save9.grid(column=0, row=2, sticky='w')
entry_save9 = ttk.Entry(frame_extract_metadata, width=40)
entry_save9.grid(column=1, row=2, sticky='w')
button_save9 = ttk.Button(frame_extract_metadata,
                          text='Save', command=save_response9)
button_save9.grid(column=2, row=2, sticky='w')

notebook.add(frame_extract_metadata, text='Extract Metadata')

if __name__ == '__main__':
    notebook.pack(expand=True, fill='both')
    root.mainloop()
