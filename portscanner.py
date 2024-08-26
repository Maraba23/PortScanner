import ipaddress as ip
import nmap
import sys
import multiprocessing
import colorama
import time
import os
import socket  # Adicionado para resolver nomes de domínio

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
    try:
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
    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error scanning port {port} on {host}: {str(e)}")

def scan_ports(host, ports):
    try:
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
    
        if 'tcp' in scanner[host]:
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
        else:
            print(colorama.Fore.RED + "  [!] No TCP ports found or accessible on the host.")
    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error scanning ports on {host}: {str(e)}")

def scan_port_range(host, start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    scan_ports(host, ports)

def scan_all_ports(host):
    try:
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
    
        if 'tcp' in scanner[host]:
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
        else:
            print(colorama.Fore.RED + "  [!] No TCP ports found or accessible on the host.")
    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error scanning all ports on {host}: {str(e)}")

def scan_vulnerabilities(host):
    try:
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
    
        if 'tcp' in scanner[host]:
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
        else:
            print(colorama.Fore.RED + "  [!] No TCP ports found or accessible on the host.")
    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error scanning vulnerabilities on {host}: {str(e)}")

def loop_ascii_art():
    counter = 0
    while counter < 2:
        for i in range(1, 5):
            os.system('cls' if os.name == 'nt' else 'clear')
            print_ascii_art(str(i))
            print("\n\n  [*] Loading...")
            time.sleep(0.8)
        counter += 1

def is_valid_port(port):
    return 1 <= port <= 65535

def main():
    loop_ascii_art()

    print("\n\n" + colorama.Fore.RESET)
    print(colorama.Fore.GREEN + "  Welcome to the Python Port Scanner!")
    host_input = input("\n\n  [+] Enter the IP or hostname to scan: ")

    # Tenta interpretar a entrada como um endereço IP
    try:
        ip_obj = ip.ip_address(host_input)
        resolved_ip = host_input
    except ValueError:
        # Se falhar, tenta resolver como hostname
        try:
            resolved_ip = socket.gethostbyname(host_input)
            print(colorama.Fore.RESET + colorama.Fore.YELLOW + f"  [*] Resolved {host_input} to {resolved_ip}")
        except socket.gaierror:
            print(colorama.Fore.RED + "  [!] Invalid hostname")
            sys.exit(1)

    # Verifica se o endereço IP é privado
    try:
        if ip.ip_address(resolved_ip).is_private:
            print(colorama.Fore.RED + "  [!] Please enter a public IP address or a hostname resolving to a public IP")
            sys.exit(1)
    except ValueError:
        print(colorama.Fore.RED + "  [!] Invalid IP address after resolution")
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
            if not is_valid_port(port):
                raise ValueError
        except ValueError:
            print(colorama.Fore.RED + "  [!] Invalid port number")
            sys.exit(1)
        scan_single_port(resolved_ip, port)
    elif scan_type == '2':
        start_port = input("  [+] Enter the starting port: ")
        end_port = input("  [+] Enter the ending port: ")
        try:
            start_port = int(start_port)
            end_port = int(end_port)
            if not (is_valid_port(start_port) and is_valid_port(end_port)):
                raise ValueError
            if start_port > end_port:
                print(colorama.Fore.RED + "  [!] Starting port should be less than or equal to ending port")
                sys.exit(1)
        except ValueError:
            print(colorama.Fore.RED + "  [!] Invalid port number")
            sys.exit(1)
        scan_port_range(resolved_ip, start_port, end_port)
    elif scan_type == '3':
        scan_all_ports(resolved_ip)
    elif scan_type == '4':
        scan_vulnerabilities(resolved_ip)
    else:
        print(colorama.Fore.RED + "  [!] Invalid choice")
        sys.exit(1)

if __name__ == '__main__':
    main()
