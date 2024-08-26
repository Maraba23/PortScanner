import ipaddress as ip
import nmap
import sys
import multiprocessing
import colorama
import time
import os

colorama.init()

ascii_art_dict = {
    '1': r"""
     /$$      /$$                              /$$                        /$$$$$$                                                             
    | $$$    /$$$                             | $$                       /$$__  $$                                                            
    | $$$$  /$$$$  /$$$$$$   /$$$$$$  /$$$$$$ | $$$$$$$   /$$$$$$       | $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
    | $$ $$/$$ $$ |____  $$ /$$__  $$|____  $$| $$__  $$ |____  $$      |  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
    | $$  $$$| $$  /$$$$$$$| $$  \__/ /$$$$$$$| $$  \ $$  /$$$$$$$       \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
    | $$\  $ | $$ /$$__  $$| $$      /$$__  $$| $$  | $$ /$$__  $$       /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
    | $$ \/  | $$|  $$$$$$$| $$     |  $$$$$$$| $$$$$$$/|  $$$$$$$      |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
    |__/     |__/ \_______/|__/      \_______/|_______/  \_______/       \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      

    """,
    '2': r"""
    $$\      $$\                              $$\                        $$$$$$\                                                             
    $$$\    $$$ |                             $$ |                      $$  __$$\                                                            
    $$$$\  $$$$ | $$$$$$\   $$$$$$\  $$$$$$\  $$$$$$$\   $$$$$$\        $$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  
    $$\$$\$$ $$ | \____$$\ $$  __$$\ \____$$\ $$  __$$\  \____$$\       \$$$$$$\  $$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
    $$ \$$$  $$ | $$$$$$$ |$$ |  \__|$$$$$$$ |$$ |  $$ | $$$$$$$ |       \____$$\ $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
    $$ |\$  /$$ |$$  __$$ |$$ |     $$  __$$ |$$ |  $$ |$$  __$$ |      $$\   $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
    $$ | \_/ $$ |\$$$$$$$ |$$ |     \$$$$$$$ |$$$$$$$  |\$$$$$$$ |      \$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
    \__|     \__| \_______|\__|      \_______|\_______/  \_______|       \______/  \_______|\_______|\__|  \__|\__|  \__| \_______|\__|     

    """,
    '3': r"""
     __       __                               __                         ______                                                             
    |  \     /  \                             |  \                       /      \                                                            
    | $$\   /  $$  ______    ______   ______  | $$____    ______        |  $$$$$$\  _______  ______   _______   _______    ______    ______  
    | $$$\ /  $$$ |      \  /      \ |      \ | $$    \  |      \       | $$___\$$ /       \|      \ |       \ |       \  /      \  /      \ 
    | $$$$\  $$$$  \$$$$$$\|  $$$$$$\ \$$$$$$\| $$$$$$$\  \$$$$$$\       \$$    \ |  $$$$$$$ \$$$$$$\| $$$$$$$\| $$$$$$$\|  $$$$$$\|  $$$$$$\
    | $$\$$ $$ $$ /      $$| $$   \$$/      $$| $$  | $$ /      $$       _\$$$$$$\| $$      /      $$| $$  | $$| $$  | $$| $$    $$| $$   \$$
    | $$ \$$$| $$|  $$$$$$$| $$     |  $$$$$$$| $$__/ $$|  $$$$$$$      |  \__| $$| $$_____|  $$$$$$$| $$  | $$| $$  | $$| $$$$$$$$| $$      
    | $$  \$ | $$ \$$    $$| $$      \$$    $$| $$    $$ \$$    $$       \$$    $$ \$$     \\$$    $$| $$  | $$| $$  | $$ \$$     \| $$      
     \$$      \$$  \$$$$$$$ \$$       \$$$$$$$ \$$$$$$$   \$$$$$$$        \$$$$$$   \$$$$$$$ \$$$$$$$ \$$   \$$ \$$   \$$  \$$$$$$$ \$$      
    """,
    '4': r"""
     __       __                               __                         ______                                                              
    /  \     /  |                             /  |                       /      \                                                             
    $$  \   /$$ |  ______    ______   ______  $$ |____    ______        /$$$$$$  |  _______   ______   _______   _______    ______    ______  
    $$$  \ /$$$ | /      \  /      \ /      \ $$      \  /      \       $$ \__$$/  /       | /      \ /       \ /       \  /      \  /      \ 
    $$$$  /$$$$ | $$$$$$  |/$$$$$$  |$$$$$$  |$$$$$$$  | $$$$$$  |      $$      \ /$$$$$$$/  $$$$$$  |$$$$$$$  |$$$$$$$  |/$$$$$$  |/$$$$$$  |
    $$ $$ $$/$$ | /    $$ |$$ |  $$/ /    $$ |$$ |  $$ | /    $$ |       $$$$$$  |$$ |       /    $$ |$$ |  $$ |$$ |  $$ |$$    $$ |$$ |  $$/ 
    $$ |$$$/ $$ |/$$$$$$$ |$$ |     /$$$$$$$ |$$ |__$$ |/$$$$$$$ |      /  \__$$ |$$ \_____ /$$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$/ $$ |      
    $$ | $/  $$ |$$    $$ |$$ |     $$    $$ |$$    $$/ $$    $$ |      $$    $$/ $$       |$$    $$ |$$ |  $$ |$$ |  $$ |$$       |$$ |      
    $$/      $$/  $$$$$$$/ $$/       $$$$$$$/ $$$$$$$/   $$$$$$$/        $$$$$$/   $$$$$$$/  $$$$$$$/ $$/   $$/ $$/   $$/  $$$$$$$/ $$/       
    """,
}

def print_ascii_art(art_number):
    print(ascii_art_dict[art_number])

def scan_single_port(host, port):
    scanner = nmap.PortScanner()
    print(colorama.Fore.RESET + colorama.Fore.MAGENTA + f"  [+] Scanning port {port} on {host}")
    scanner.scan(host, str(port))
    state = scanner[host]['tcp'][int(port)]['state']
    print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
    [*] Port {port} is {state}\n
    ==========PORT INFO==========
    [!] Host Name: {scanner[host]['hostnames'][0]['name']}
    [!] Host Name Type: {scanner[host]['hostnames'][0]['type']}
    [!] Status: {scanner[host]['status']['state']}
    [!] Status Reason: {scanner[host]['status']['reason']}
    [!] TCP State: {scanner[host]['tcp'][int(port)]['state']}
    [!] TCP Reason: {scanner[host]['tcp'][int(port)]['reason']}
    [!] TCP Name: {scanner[host]['tcp'][int(port)]['name']}

    =============================
    """
    )

def scan_ports(host, ports):
    scanner = nmap.PortScanner()
    port_string = f'{ports[0]}-{ports[-1]}'
    print(colorama.Fore.RESET + colorama.Fore.MAGENTA + f"  [+] Scanning ports {port_string} on {host}")
    scanner.scan(host, port_string)
    print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
    [!] Host Name: {scanner[host]['hostnames'][0]['name']}
    [!] Host Name Type: {scanner[host]['hostnames'][0]['type']}
    [!] Status: {scanner[host]['status']['state']}
    [!] Status Reason: {scanner[host]['status']['reason']}
    =============================
    """
    )

    for port in scanner[host]['tcp']:
        state = scanner[host]['tcp'][int(port)]['state']
        print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
        [*] Port {port} is {state}\n
        ==========PORT INFO==========
        [!] TCP State: {scanner[host]['tcp'][int(port)]['state']}
        [!] TCP Reason: {scanner[host]['tcp'][int(port)]['reason']}
        [!] TCP Name: {scanner[host]['tcp'][int(port)]['name']}

        =============================
        """
        )

def scan_port_range(host, start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    scan_ports(host, ports)

def scan_all_ports(host):
    scanner = nmap.PortScanner()
    print(colorama.Fore.RESET + colorama.Fore.MAGENTA + f"  [+] Scanning all ports on {host}")
    scanner.scan(host, '1-65535')
    print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
    [!] Host Name: {scanner[host]['hostnames'][0]['name']}
    [!] Host Name Type: {scanner[host]['hostnames'][0]['type']}
    [!] Status: {scanner[host]['status']['state']}
    [!] Status Reason: {scanner[host]['status']['reason']}
    =============================
    """
    )

    for port in scanner[host]['tcp']:
        state = scanner[host]['tcp'][int(port)]['state']
        print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
        [*] Port {port} is {state}\n
        ==========PORT INFO==========
        [!] TCP State: {scanner[host]['tcp'][int(port)]['state']}
        [!] TCP Reason: {scanner[host]['tcp'][int(port)]['reason']}
        [!] TCP Name: {scanner[host]['tcp'][int(port)]['name']}

        =============================
        """
        )


def scan_vulnerabilities(host):
    scanner = nmap.PortScanner()
    print(colorama.Fore.RESET + colorama.Fore.MAGENTA + f"  [+] Scanning for vulnerabilities on {host}")
    scanner.scan(host, arguments="--script vuln")
    print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
    [!] Host Name: {scanner[host]['hostnames'][0]['name']}
    [!] Host Name Type: {scanner[host]['hostnames'][0]['type']}
    [!] Status: {scanner[host]['status']['state']}
    [!] Status Reason: {scanner[host]['status']['reason']}
    =============================
    """)

    for port in scanner[host].all_tcp():
        state = scanner[host]['tcp'][int(port)]['state']
        print(colorama.Fore.RESET + colorama.Fore.BLUE + f"""
        [*] Port {port} is {state}\n
        ==========VULNERABILITY INFO==========
        """)
        if 'script' in scanner[host]['tcp'][port]:
            for script in scanner[host]['tcp'][port]['script']:
                print(colorama.Fore.RESET + colorama.Fore.RED + f"[!] {script}: {scanner[host]['tcp'][port]['script'][script]}")
        print("\n=============================\n")

def loop_ascii_art():
    counter = 0
    while counter < 2:
        for i in range(1, 5):
            os.system('cls' if os.name == 'nt' else 'clear')
            print_ascii_art(str(i))
            print("\n\n  [*] Loading...")
            time.sleep(0.8)
        counter += 1

            
        

def main():
    loop_ascii_art()

    print("\n\n" + colorama.Fore.RESET)
    print(colorama.Fore.GREEN + "  Welcome to the Python Port Scanner!")
    host = input("\n\n  [+] Enter the ip to scan: ")

    try:
        if ip.ip_address(host).is_private:
            print("  [!] Please enter a public IP address")
            sys.exit(1)
    except ValueError:
        print("  [!] Invalid IP address")
        sys.exit(1)

    print("\n  [+] Choose a scan type:")
    print("      1. Scan a single port")
    print("      2. Scan a range of ports")
    print("      3. Scan all ports")
    print("      4. Scan for vulnerabilities")
    scan_type = input("\n  [+] Enter your choice: ")

    if scan_type == '1':
        port = input("  [+] Enter the port to scan: ")
        try:
            port = int(port)
        except ValueError:
            print("  [!] Invalid port number")
            sys.exit(1)
        scan_single_port(host, port)
    elif scan_type == '2':
        start_port = input("  [+] Enter the starting port: ")
        end_port = input("  [+] Enter the ending port: ")
        try:
            start_port = int(start_port)
            end_port = int(end_port)
        except ValueError:
            print("  [!] Invalid port number")
            sys.exit(1)
        scan_port_range(host, start_port, end_port)
    elif scan_type == '3':
        scan_all_ports(host)
    elif scan_type == '4':
        scan_vulnerabilities(host)
    else:
        print("  [!] Invalid choice")
        sys.exit(1)

if __name__ == '__main__':
    main() 
