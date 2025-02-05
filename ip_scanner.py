#!/usr/bin/env python3
# Import libraries
import argparse
import ipaddress
import subprocess
import platform
import socket
import sys
import re
import concurrent.futures

# Variable ping
def ping(ip):
    # Send one ping to the given IP address; return True if responsive.
    param = "-n" if platform.system().lower() == "windows" else "-c"
    # Tries to run ping command with 1,-w,1 arguments and return True if returncode is 0
    try:
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    # If there is an exception, return False
    except Exception:
        return False

def get_live_hosts(cidr):
    """
    Returns a list of host IP addresses in the given CIDR that respond to ping.
    Uses concurrent threads to ping all hosts in parallel.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    all_hosts = list(network.hosts())
    live_hosts = []
    print(f"Scanning network {cidr} concurrently for live hosts...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(ping, str(ip)): str(ip) for ip in all_hosts}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip_str = future_to_ip[future]
            try:
                if future.result():
                    live_hosts.append(ip_str)
                    print(f"[+] {ip_str} (UP)")
                else:
                    print(f"[-] {ip_str} (DOWN)")
            except Exception as exc:
                print(f"[-] {ip_str} generated an exception: {exc}")

    return live_hosts

def parse_ports(port_arg):
    """
    Parse the port argument.
    Supported formats:
      - Single port: "80"
      - Range: "1-100"
      - Comma-separated: "80,443,3306" (with or without spaces)
    Returns a sorted list of unique integer port numbers.
    """
    # Empty unordered list to store
    ports = set()
    # Remove any whitespace
    port_arg = port_arg.replace(" ", "")
    if '-' in port_arg and ',' not in port_arg:
        # Port range, e.g., "1-100"
        # Tries to start and end the range at the given port numbers
        try:
            start, end = map(int, port_arg.split('-'))
            ports.update(range(start, end + 1))
            # Error handling for invalid port range
        except ValueError:
            print("Error: Invalid port range format. Use something like '1-100'.")
            sys.exit(1)
            # Else if there is a comma in the port argument then go through the set list
    elif ',' in port_arg:
        # Comma-separated list, e.g., "80,443,3306"
        for p in port_arg.split(','):
            try:
                ports.add(int(p))
            except ValueError:
                print("Error: Invalid port number in list.")
                sys.exit(1)
    else:
        # Single port, e.g., "80"
        try:
            ports.add(int(port_arg))
        except ValueError:
            print("Error: Invalid port number.")
            sys.exit(1)
    # Validate port numbers are within 1-65535
    for port in ports:
        if port < 1 or port > 65535:
            print(f"Error: Port {port} is out of range (1-65535).")
            sys.exit(1)
    return sorted(ports)

def scan_ports(host, ports):
    """
    Scan the specified ports on the given host.
    Returns a list of open ports.
    """
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # 1-second timeout per port
        try:
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

def get_service_name(port):
    """
    Return the standard service name for the given port.
    If not found, returns 'UNKNOWN'.
    """
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "UNKNOWN"

def scan_ports_for_host(host, ports):
    """Scan the specified ports on one host and return the open ports with their service names."""
    open_ports = scan_ports(host, ports)
    services = {port: get_service_name(port) for port in open_ports}
    return services

def scan_ports_concurrently(live_hosts, ports):
    """
    Scan ports for all live hosts concurrently.
    Returns a dictionary mapping host -> {port: service}.
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_host = {executor.submit(scan_ports_for_host, host, ports): host for host in live_hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                results[host] = future.result()
            except Exception as exc:
                print(f"Error scanning ports for {host}: {exc}")
                results[host] = {}
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Scan a CIDR for live hosts and then scan specified ports on each live host, reporting the standard service for each open port.",
        epilog="""Usage Examples:
  ./ip_scanner.py -p 80,443,3306 192.168.1.0/24
  ./ip_scanner.py -p 1-100 192.168.1.0/24
  -h, --help for this message."""
    )
    parser.add_argument(
        "-p", "--ports",
        required=True,
        help="Port(s) to scan. Accepts a single port (e.g., 80), a range (e.g., 1-100), or a comma-separated list (e.g., 80,443,3306)."
    )
    parser.add_argument(
        "cidr",
        help="CIDR notation for the network to scan (e.g., 192.168.1.0/24)."
    )
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"Ports to scan: {ports}\n")
    
    live_hosts = get_live_hosts(args.cidr)
    if not live_hosts:
        print("No live hosts found in the network.")
        sys.exit(0)
    
    print("\nScanning ports on live hosts concurrently...")
    port_scan_results = scan_ports_concurrently(live_hosts, ports)
    
    print("\nPort scan results:")
    for host in live_hosts:
        print(f"{host}  (UP)")
        host_services = port_scan_results.get(host, {})
        if host_services:
            for port in sorted(host_services.keys()):
                service = host_services[port]
                print(f"  - Port {port}   (OPEN - {service})")
        else:
            print("  - No specified ports are open.")

if __name__ == "__main__":
    main()
