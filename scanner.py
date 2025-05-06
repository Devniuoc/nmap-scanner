#!/usr/bin/python3

import nmap
import os

# Initialize the scanner
scanner = nmap.PortScanner()

def save_results(filename, content):
    """Save scan results to a file."""
    with open(filename, 'w') as file:
        file.write(content)
    print(f"Results saved to {filename}")

def scan_single_ip(scanner, ip_addr, scan_type):
    """Perform a scan on a single IP address."""
    print("Nmap Version: ", scanner.nmap_version())
    try:
        if scan_type == '1':
            scanner.scan(ip_addr, '1-100', '-v -sS', sudo=True)
        elif scan_type == '2':
            scanner.scan(ip_addr, '1-250', '-v -sU', sudo=True)
        elif scan_type == '3':
            scanner.scan(ip_addr, '1-100', '-v -sS -sV -sC -A -O', sudo=True)
        elif scan_type == '4':
            scanner.scan(ip_addr, '1-100', '-sV', sudo=True)

        # Print Results
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ip_addr].state())
        print("Available Protocols: ", scanner[ip_addr].all_protocols())

        # Check protocols and open ports
        for protocol in scanner[ip_addr].all_protocols():
            print(f"Open {protocol.upper()} Ports: ", scanner[ip_addr][protocol].keys())

        # Save to a file
        save_results(f"scan_results_{ip_addr}.txt", scanner[ip_addr].__str__())

    except Exception as e:
        print(f"Error: {e}")

print("Welcome, this is an advanced nmap automation tool")
print("<--------------------------------------------------->")

# Choose an operation mode
mode = input("""Please choose a mode:
                    1) Scan a Single IP
                    2) Scan Multiple IPs
                    3) Scan a Network Range\n""")

if mode == '1':
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)

    resp = input(""" \nPlease enter the type of scan you want to run:
                        1) SYN ACK Scan
                        2) UDP Scan
                        3) Comprehensive Scan
                        4) Service Detection\n""")
    print("You have selected option: ", resp)

    if resp in ['1', '2', '3', '4']:
        scan_single_ip(scanner, ip_addr, resp)
    else:
        print("Invalid option selected!")

elif mode == '2':
    ips = input("Please enter IP addresses to scan (comma-separated): ").split(',')
    for ip in ips:
        print(f"\nScanning IP: {ip.strip()}")
        scan_single_ip(scanner, ip.strip(), '3')  # Default to comprehensive scan

elif mode == '3':
    network_range = input("Please enter the network range to scan (e.g., 192.168.1.0/24): ")
    print(f"Scanning Network Range: {network_range}")
    try:
        scanner.scan(hosts=network_range, arguments='-v -sS', sudo=True)
        for host in scanner.all_hosts():
            print(f"\nHost: {host}")
            print(f"Status: {scanner[host].state()}")
            print(f"Protocols: {scanner[host].all_protocols()}")
            for protocol in scanner[host].all_protocols():
                print(f"Open {protocol.upper()} Ports: ", scanner[host][protocol].keys())
    except Exception as e:
        print(f"Error: {e}")

else:
    print("Invalid mode selected. Please restart the program.")

print("Scan Complete.")
