import socket
import re
import ssl
import sys
import time
# Function to parse nmap-services file
def parse_nmap_services(file_path):
    services = {}
    with open(file_path, 'r') as file:
        for line in file:
            if not line.startswith("#") and line.strip():
                parts = line.split()
                service_name = parts[0]
                port_proto = parts[1]
                port = int(port_proto.split('/')[0])
                services[port] = service_name
    return services

# Dictionary of common ports and their associated services
nmap_services = parse_nmap_services('nmap-services')

def is_valid_ip(ip):
    # Regex pattern to match a valid IP address
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def get_ip_from_user():
    ip = sys.argv[1]
    return ip
    #while True:
    #    ip = input("Enter the target IP address: ").strip()
    #    if is_valid_ip(ip):
    #        return ip
    #    else:
    #        print("Invalid IP address. Please enter a valid IP address.")

def scan_ports(ip, start_port, end_port):
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        return open_ports
    except socket.gaierror:
        print("Host is unreachable.")
        return None

def get_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b'\n')
            banner = s.recv(1024).decode().strip()
            return banner
    except:
        return None

def get_http_version(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode())
            response = s.recv(1024).decode()
            version = response.split('\r\n')[0]
            return version
    except:
        return None

def get_https_version(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.settimeout(1)
                ssock.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode())
                response = ssock.recv(1024).decode()
                version = response.split('\r\n')[0]
                return version
    except:
        return None

def get_rtsp_version(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b"OPTIONS rtsp://{}:554 RTSP/1.0\r\nCSeq: 1\r\n\r\n".format(ip).encode())
            response = s.recv(1024).decode()
            version = response.split('\r\n')[0]
            return version
    except:
        return None

def main():
    ip = get_ip_from_user()
    start_port = 1
    end_port = 10000
    
    st = time.time()
    print(f"Scanning {ip} from port {start_port} to {end_port}...")
    open_ports = scan_ports(ip, start_port, end_port)
    
    if open_ports is None:
        return
    
    if not open_ports:
        print("All ports are closed.")
        return
    
    print("PORT     STATE SERVICE VERSION")
    for port in open_ports:
        service_name = nmap_services.get(port, 'unknown')
        version = None
        
        if port == 80:
            version = get_http_version(ip, port)
        elif port == 443:
            version = get_https_version(ip, port)
        elif port == 554:
            version = get_rtsp_version(ip, port)
        
        if version:
            print(f"{port}/tcp   open  {service_name} {version}")
        else:
            banner = get_banner(ip, port)
            if banner:
                print(f"{port}/tcp   open  {service_name} {banner}")
            else:
                print(f"{port}/tcp   open  {service_name}")
    end = time.time()
    duration = end - st 
    print(f"duration of scanning is {duration:.2f}")
if __name__ == "__main__":
    main()

