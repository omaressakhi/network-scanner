import scapy.all as scapy
import argparse
import threading
import time
import socket
import os
import sys
import platform
import tabulate
import colorama
from tabulate import tabulate
from colorama import Fore, Style
# Import the os module for file existence check
# Dictionary of common ports and their services
port_names = {
    7: "echo", 9: "discard", 19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh/scp/sftp", 23: "telnet", 25: "smtp",
    42: "wins replication", 43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp/bootp", 68: "dhcp/bootp", 69: "tftp",
    70: "gopher", 79: "finger", 80: "http", 88: "kerberos", 101: "hostname", 102: "microsoft exchange iso-tsap",
    110: "pop3", 113: "ident", 119: "nntp (usenet)", 123: "ntp", 135: "microsoft rpc epmap", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp-agents (unencrypted)", 162: "snmp-trap (unencrypted)",
    177: "xdmcp", 179: "bgp", 194: "irc", 201: "appletalk", 264: "bgmp", 318: "tsp", 381: "hp openview", 383: "hp openview",
    389: "ldap", 411: "multiple uses", 412: "multiple uses", 427: "sip", 443: "https (http over ssl)", 445: "microsoft ds smb",
    464: "kerberos", 465: "smtp over ssl", 497: "dantz retrospect", 500: "ipsec/isakmp/ike", 512: "rexec", 513: "rlogin",
    514: "syslog/shell", 515: "lpd/lpr", 520: "rip", 521: "ripv6", 540: "uucp", 546: "dhcpv6", 547: "dhcpv6", 548: "afp",
    554: "rtsp", 560: "monitor", 563: "nntp over ssl", 587: "smtp/submission", 591: "filemaker", 593: "microsoft doom",
    596: "smsd", 631: "ipp", 636: "ldap over ssl", 639: "msdp (plm)", 646: "ldp (mpls)", 691: "microsoft exchange",
    860: "iscsi", 873: "rsync", 902: "vmware server", 989: "ftps", 990: "ftps", 992: "telnets", 993: "imap over ssl (imaps)",
    995: "pop3 over ssl (pop3s)", 1025: "microsoft rpc", 1080: "socks", 1194: "openvpn", 1241: "nessus", 1311: "dell openmanage",
    1433: "ms-sql-s", 1434: "ms-sql-m", 1494: "ica", 1512: "wins", 1524: "ingreslock", 1589: "cisco vqp", 1701: "l2tp",
    1719: "h323gatestat", 1720: "h323hostcall", 1723: "microsoft pptp", 1725: "steam", 1755: "mms", 1812: "radius",
    1813: "radius-acct", 1900: "upnp", 1947: "sip-tls", 1985: "hsrp", 2000: "cisco sccp", 2002: "cisco acs", 2008: "teamspeak 3 accounting",
    2010: "teamspeak 3 web list", 2049: "nfs", 2082: "cpanel", 2083: "radsec/cpanel", 2100: "amiganets", 2102: "zephyr-srv",
    2103: "zephyr-clt", 2104: "zephyr-hm", 2222: "directadmin", 2401: "cvspserver", 2483: "oracle", 2484: "oracle", 2809: "corbaloc",
    2869: "upnp", 2967: "symantec av", 3128: "http proxy", 3222: "glbp", 3260: "iscsi target", 3306: "mysql", 3389: "rdp",
    3689: "daap", 3690: "svn", 4321: "rwhois", 4333: "msql", 4500: "ipsec nat traversal", 4899: "radmin", 5000: "upnp",
    5001: "iperf", 5004: "rtp", 5005: "rtp", 5060: "sip", 5061: "sip-tls", 5222: "xmpp", 5223: "xmpp", 5353: "mdns",
    5357: "wsdapi", 5432: "postgresql", 5800: "vnc over http", 5900: "vnc", 5999: "cvsup", 6000: "x11", 6001: "x11",
    6129: "dameware", 6379: "redis", 6588: "analogx", 8080: "http proxy", 8200: "vmware server", 8222: "vmware server",
    8767: "teamspeak", 9042: "cassandra", 9100: "pdl", 9800: "webdav", 10161: "snmp-agents", 10162: "snmp-trap",
    13720: "bord", 13721: "bpdbm", 13724: "vnetd", 13782: "bpcd", 13783: "vopied", 20000: "usermin", 22273: "wnn6",
    23399: "skype", 25565: "minecraft", 27017: "mongodb", 33434: "traceroute"
}
common_ports = list(port_names.keys())
open_ports = []


def get_arguments():
    parser = argparse.ArgumentParser(description="Network scanner tool")
    parser.add_argument("-s", "--network", help="The IP network to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--scan_port", help="Scan the top port popular")
    parser.add_argument("-a", "--scan_address", help="Scan a specific IP address")
    parser.add_argument("-r", "--scan_range", help="Scan a range of ports (e.g., 1-100)")
    parser.add_argument("-o", "--os_detection",  help="Enable OS detection (not implemented)")
    parser.add_argument("-i","--scan_all_ports",  help="Scan all ports (1-65535)")
    return parser.parse_args()
def is_host_reachable(ip, port=80):
    print(f"{Fore.CYAN}[*] Checking host: {ip} on port {port}...{Style.RESET_ALL}")

    # 1. Check via Ping (ICMP)
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    ping_result = os.system(f"ping {param} {ip} > /dev/null 2>&1")

    # 2. Check via TCP Connection
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.settimeout(2)  # 2 seconds timeout
    tcp_result = tcp_socket.connect_ex((ip, port))  # 0 means success
    tcp_socket.close()

    if ping_result == 0 or tcp_result == 0:
        print(f"{Fore.GREEN}[+] {ip} is UP ✅{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] {ip} is DOWN ❌{Style.RESET_ALL}")

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port} ({port_names.get(port, 'unknown')}) is open")
        sock.close()
    except socket.error:
        pass


def scan_ports(host, ports):
    print(f"Scanning ports on {host}...")
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(host, port))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    if not open_ports:
        print("All ports are closed or filtered")


def scan(network):
    arp_request = scapy.ARP(pdst=network)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast / arp_request
    answer = scapy.srp(arp_request_broadcast, verbose=False, timeout=2)[0]
    client_list = []
    x=1
    for ans in answer:
        client_dic = {"ip": ans[1].psrc, "mac": ans[1].hwsrc}
        client_list.append(client_dic)
    if x == 1:
        client_dic1 = {"ip": ans[1].pdst, "mac": ans[1].hwdst}
        client_list.append(client_dic1)
    x += 1
    return client_list



def resolve_mac_vendor(mac, oui_file='ieee-oui.txt'):
    try:
        if mac is None:
            return "MAC Address Not Found"

        mac_address = mac.replace(':', '').replace('-', '').upper()
        oui = mac_address[:6]

        if not os.path.exists(oui_file):
            return "Unknown"

        with open(oui_file, 'r') as f:
            oui_db = f.readlines()

        for line in oui_db:
            if oui in line:
                return line.split('\t')[-1].strip()
        return "Unknown"
    except Exception as e:
        return f"Error: {e}"

def get_mac(ip):
    # If the IP matches the machine's own IP, use an alternative method
    if ip == scapy.get_if_addr(scapy.conf.iface):
        return scapy.get_if_hwaddr(scapy.conf.iface)

    # Normal ARP request for other devices
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None





def affiche(clients, network):
    headers = [f"{Fore.CYAN}IP Address{Style.RESET_ALL}",
               f"{Fore.YELLOW}MAC Address{Style.RESET_ALL}",
               f"{Fore.GREEN}Vendor{Style.RESET_ALL}"]

    table_data = []

    for client in clients:
        vendor = resolve_mac_vendor(client['mac'])

        # Add colors to IP, MAC, and Vendor
        colored_ip = f"{Fore.CYAN}{client['ip']}{Style.RESET_ALL}"
        colored_mac = f"{Fore.YELLOW}{client['mac']}{Style.RESET_ALL}"
        colored_vendor = f"{Fore.GREEN}{vendor}{Style.RESET_ALL}"

        table_data.append([colored_ip, colored_mac, colored_vendor])

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}🔍 Scanning Network: {network}{Style.RESET_ALL}\n")
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

def threaded_scan(network):
    start_time = time.time()
    clients = scan(network)
    end_time = time.time()
    affiche(clients, network)
    print("\nScan completed!")
    print(f"Time taken: {end_time - start_time:.2f} seconds")
    print(f"Number of hosts found: {len(clients)}")


def main():
    options = get_arguments()
    colorama.init(autoreset=True)

    if options.scan_range:
        try:
            # Extracting port range from user input
            ports = list(map(int, options.scan_range.split('-')))

            # Validating port range format
            if len(ports) == 2 and ports[0] <= ports[1]:
                print(
                    f"\n{Fore.CYAN}{Style.BRIGHT}🔍 Scanning ports from {Fore.YELLOW}{ports[0]} to {ports[1]}{Fore.CYAN} on {Fore.GREEN}{options.scan_address}...{Style.RESET_ALL}\n")
                scan_ports(options.scan_address, range(ports[0], ports[1] + 1))
            else:
                print(f"\n{Fore.RED}{Style.BRIGHT}[❌ Error] Invalid port range format!{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}➡ Correct format: 'start-end' (e.g., 1-100).{Style.RESET_ALL}\n")
        except ValueError:
            print(f"\n{Fore.RED}{Style.BRIGHT}[❌ Error] Invalid port range format!{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}➡ Correct format: 'start-end' (e.g., 1-100).{Style.RESET_ALL}\n")

        sys.exit()
    if options.network:
        scan_thread = threading.Thread(target=threaded_scan, args=(options.network,))
        scan_thread.start()
        scan_thread.join()
        sys.exit()
    if options.scan_address:
        is_host_reachable(options.scan_address,port=80)
        sys.exit()
    if options.scan_port:
            scan_ports(options.scan_port, port_names)
    if options.os_detection:
        mac_address = get_mac(options.os_detection)

        if mac_address:
            vendor_name = resolve_mac_vendor(mac_address)

            # Data for table (Without Hostname)
            data = [[options.os_detection, mac_address, vendor_name]]

            # Print formatted table
            print("\nNetwork Device Info:")
            print(tabulate(data, headers=["IP Address", "MAC Address", "Vendor"], tablefmt="grid"))
        else:
            print(f"Could not find MAC address for IP {options.os_detection}. The host may be down.")
    if options.scan_all_ports:
        scan_ports(options.scan_all_ports, range(1, 65536))  # Scan all ports
    else:
        try:
            start, end = map(int, options.scan_range.split('-'))
            if 1 <= start <= end <= 65535:
                scan_ports(options.scan_address, range(start, end + 1))
            else:
                print("❌ Invalid port range. Use 'start-end' (e.g., 5-100).")
        except ValueError:
            print("❌ Invalid format. Use 'start-end' (e.g., 5-100).")


if __name__ == "__main__":
    main()