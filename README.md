# Python Port Scanner

This is a simple Python script for scanning ports on a target IP address or hostname. It supports scanning TCP ports, detecting service versions (banner grabbing), and can be configured to scan specific port ranges or lists.

## Requirements

- Python 3.x
- socket` module (standard library)
- argparse` module (standard library)

## Usage

1. **Clone the repository:**
git clone https://github.com/WhoIsEtomica/python-port-scanner.git
cd python-port-scanner
Run the script:
python port_scanner.py target_ip_or_hostname [options]
Replace target_ip_or_hostname with the IP address or hostname you want to scan.

Options:

-p, --ports: Specify ports to scan. Use a range (e.g., 1-1024) or a comma-separated list (e.g., 20,22,80).
--tcp: Use TCP protocol (default).
--udp: Use UDP protocol (not fully implemented).
--version: Detect service versions (banner grabbing).
--os: Detect OS of the target (not implemented).
Examples:

Scan common ports (1-1024) on a target:
python port_scanner.py 192.168.1.1
Scan specific ports (20, 22, 80) and detect service versions:
python port_scanner.py example.com -p 20,22,80 --version
UDP scan (not fully implemented):
python port_scanner.py 192.168.1.1 --udp

# Notes
UDP scanning is currently not fully implemented in this script.
Adjust timeouts and error handling as per your specific requirements.
Use responsibly and ensure you have permission to scan the target IP address or hostname.
