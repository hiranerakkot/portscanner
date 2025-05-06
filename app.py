from flask import Flask, render_template, request
import socket
from datetime import datetime
import threading

app = Flask(__name__)

port_status = []
lock = threading.Lock()

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD Printer",
    587: "SMTP (Submission)",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MS SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    1812: "RADIUS Auth",
    1813: "RADIUS Acct",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion SVN",
    4444: "Metasploit",
    5060: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    6000: "X11",
    8080: "HTTP Alt"
}
   

def scan_port(target, port):
    status = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                status = True
    except:
        pass
    with lock:
        port_status.append({'number': port, 'is_open': status})

@app.route('/', methods=['GET', 'POST'])
def scan():
    global port_status
    result = None
    port_status = []

    port_search = request.args.get('port_search', '')  # Get search query from URL

    # Filter common ports based on search query
    if port_search.isdigit():
        port_search = int(port_search)
        common_ports = {port: name for port, name in COMMON_PORTS.items() if port == port_search}
    else:
        common_ports = COMMON_PORTS

    if request.method == 'POST':
        target = request.form['target']
        start_port = int(request.form['start_port'])
        end_port = int(request.form['end_port'])

        start_time = datetime.now()
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(target, port))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        duration = datetime.now() - start_time
        result = {
            'target': target,
            'start_port': start_port,
            'end_port': end_port,
            'duration': duration,
            'port_status': sorted(port_status, key=lambda x: x['number']),
            'open_ports': [port['number'] for port in port_status if port['is_open']]
        }

    return render_template('index.html', result=result, common_ports=common_ports, port_search=port_search)

if __name__ == '__main__':
    app.run(debug=True)
