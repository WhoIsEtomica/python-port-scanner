import argparse
import socket
import sys
import threading
from queue import Queue

def scan_worker(target, port, result_queue, scan_options):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if scan_options.tcp else socket.SOCK_DGRAM)
        sock.settimeout(1.0)  # Adjust timeout as needed

        if scan_options.detect_service_version:
            banner = b''
            if scan_options.tcp:
                sock.connect((target, port))
                banner = sock.recv(1024)
            result_queue.put((port, banner.decode().strip()))
        else:
            if sock.connect_ex((target, port)) == 0:
                result_queue.put(port)

        sock.close()
    except:
        pass

def port_scan(target, ports, scan_options):
    result_queue = Queue()
    threads = []
    
    for port in ports:
        thread = threading.Thread(target=scan_worker, args=(target, port, result_queue, scan_options))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    open_ports = []
    while not result_queue.empty():
        open_ports.append(result_queue.get())
    
    return open_ports

def parse_ports(ports_string):
    ports = []
    try:
        parts = ports_string.split(',')
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
    except ValueError:
        print(f"Invalid port range or list: {ports_string}")
        sys.exit(1)
    
    return ports

def main():
    parser = argparse.ArgumentParser(description="Simple Python port scanner")
    parser.add_argument("target", help="IP address or hostname of the target")
    parser.add_argument("-p", "--ports", metavar="PORTS", default="1-1024", 
                        help="Ports to scan. Specify a range (e.g., 1-1024) or a comma-separated list (e.g., 20,22,80)")
    parser.add_argument("--tcp", action="store_true", help="Use TCP protocol (default)")
    parser.add_argument("--udp", action="store_true", help="Use UDP protocol instead of TCP")
    parser.add_argument("--version", action="store_true", help="Detect service version (banner grabbing)")
    parser.add_argument("--os", action="store_true", help="Detect OS of the target")
    
    args = parser.parse_args()

    if args.udp:
        print("UDP scanning not implemented yet.")
        sys.exit(1)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: Unable to resolve hostname '{args.target}'.")
        sys.exit(1)

    ports = parse_ports(args.ports)

    scan_options = argparse.Namespace(tcp=True, udp=False, detect_service_version=args.version)

    if args.udp:
        scan_options.tcp = False
        scan_options.udp = True

    open_ports = port_scan(target_ip, ports, scan_options)

    if open_ports:
        print(f"Open ports on {args.target}:")
        for port in open_ports:
            if isinstance(port, tuple):  # Version detection mode
                print(f"Port {port[0]}: {port[1]}")
            else:
                print(f"Port {port} is open.")
    else:
        print(f"No open ports found on {args.target}.")

if __name__ == "__main__":
    main()