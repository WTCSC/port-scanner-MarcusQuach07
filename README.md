# IP & Port Scanner
### Description

This Python script scans a network (provided in CIDR notation) for live hosts and then scans each live host for specified ports. It reports which ports are open along with the standard service name for each open port. The script supports flexible port input formats, including single ports (e.g., 80), ranges (e.g., 1-100), and comma-separated lists (e.g., 80,443,3306). Scanning of hosts and ports is done concurrently to speed up the process.
Installation & Dependencies

### Prerequisites:

    Python 3.x
    Works on Windows, macOS, and Linux
    The "ping" command must be accessible from the command line
    "arp-scan" is required if you plan to use additional network scanning functionality (not used by default in this script, but may be added later)

### Installation:

    Clone the repository or download the script: git clone https://github.com/yourusername/ip-port-scanner.git cd ip-port-scanner

    Make the script executable (optional): chmod +x ip_scanner.py

    (Optional) Create a virtual environment and install dependencies: This script uses only Python’s built-in modules, so no extra packages are required.

### Usage

    Running the Script: The script uses command-line arguments. Use -h or --help for full help: ./ip_scanner.py -h

    Basic Command Syntax: sudo ./ip_scanner.py -p <ports> <cidr>

### Where:

    <ports>: Port(s) to scan. Accepts a single port (e.g., 80), a range (e.g., 1-100), or a comma-separated list (e.g., 80,443,3306).
    <cidr>: The network to scan in CIDR notation (e.g., 192.168.1.0/24).

### Example Commands:

    Scan specific ports: sudo ./ip_scanner.py -p 80,443,3306 192.168.1.0/24

    Scan a range of ports: sudo ./ip_scanner.py -p 1-100 192.168.1.0/24

### Example Output Format: Ports to scan: [80, 443, 3306]

    Scanning network 192.168.1.0/24 concurrently for live hosts... [+] 192.168.1.10 (UP) [-] 192.168.1.11 (DOWN) [+] 192.168.1.13 (UP) ...
  
    Scanning ports on live hosts concurrently...

    Port scan results: 192.168.1.10 (UP)

    Port 80 (OPEN - HTTP)
    Port 443 (OPEN - HTTPS) 192.168.1.13 (UP)
    Port 80 (OPEN - HTTP)
    Port 3306 (OPEN - MYSQL)

### Error Handling & Validation

    CIDR Validation: The script uses the ipaddress module to ensure the CIDR notation is valid. If invalid, it prints an error and exits.

    Port Input Validation: The script supports single ports, ranges, or comma-separated lists. It checks that each port is an integer between 1 and 65535; otherwise, it exits with an error message.

    Ping & Host Discovery: If a host does not respond to ping, it is marked as down. Any exceptions during pinging or scanning are caught and reported.

    Service Name Lookup: For each open port, the script attempts to look up the standard service name using socket.getservbyport(). If the service cannot be found, it returns "UNKNOWN."

### Troubleshooting

    Permission Issues: Changing network settings and pinging often require administrative privileges. Run the script with sudo on Linux/macOS: sudo ./ip_scanner.py -p 80 192.168.1.0/24

    No Hosts Detected:
        Verify that the target network is active.
        Ensure that firewalls or network policies are not blocking ICMP (ping) requests.

    Port Scan Not Working:
        Make sure the specified ports are correct and that the target hosts have those ports open.
        Increase the socket timeout if needed (currently set to 1 second).

    Service Name Lookup Fails:
        Some ports might not have a standard service associated; in such cases, the script reports "UNKNOWN."

License

This project is licensed under the MIT License.

[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=18052685)
