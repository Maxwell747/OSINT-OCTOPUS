import nmap

nm = nmap.PortScanner()


def run_nmap(hosts: str = '127.0.0.1',
             ports: str | None = None,
             arguments: str = '-A',
             timeout: int = 0) -> str:
    nm.scan(hosts, ports, arguments, False, timeout)

    result = {}
    for host in nm.all_hosts():
        host_data = {}
        host_data['hostname'] = nm[host].hostname()
        host_data['state'] = nm[host].state()

        protocols = {}
        for proto in nm[host].all_protocols():
            protocol_data = {}
            protocol_data['ports'] = {}
            for port in nm[host][proto].keys():
                port_data = {}
                port_data['state'] = nm[host][proto][port]['state']
                protocol_data['ports'][port] = port_data
            protocols[proto] = protocol_data

        host_data['protocols'] = protocols
        result[host] = host_data

    return nm.csv()
