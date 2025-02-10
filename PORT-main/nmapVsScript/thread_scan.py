import socket
import re
import ssl
import sys
import subprocess
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logging.basicConfig(level=logging.ERROR)

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

nmap_services = parse_nmap_services('nmap-services')

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def get_ip_from_user():
    ip = sys.argv[1]
    return ip

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                service_name = nmap_services.get(port, 'unknown')
                version = None
                if port == 80:
                    version = get_http_version(ip, port)
                elif port == 443:
                    version = get_https_version(ip, port)
                elif port == 554:
                    version = get_rtsp_version(ip, port)
                if version:
                    return f"{port}/tcp   open  {service_name} {version}"
                else:
                    banner = get_banner(ip, port)
                    if banner:
                        return f"{port}/tcp   open  {service_name} {banner}"
                    else:
                        return f"{port}/tcp   open  {service_name}"
    except socket.timeout:
        logging.warning(f"Timeout occured while scanning port {port}")
    except Exception as e:
        logging.error(f"Error occured while scanning port {port}: {e}")

    return None

def get_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b'\n')
            banner = s.recv(1024).decode().strip()
            return banner
    except socket.timeout:
        logging.error(f"Banner grab timed out on port {port}")
    except Exception as e:
        logging.error(f"Error getting banner on port {port}: {e}")
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
    except socket.timeout:
        logging.error(f"HTTP version check timed out on port {port}")
    except Exception as e:
        logging.error(f"Error getting HTTP version on port {port}: {e}")
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
    except ssl.SSLError as e:
        logging.error(f"SSL error on port {port}: {e}")
    except socket.timeout:
        logging.error(f"HTTPS version check timed out on port {port}")
    except Exception as e:
        logging.error(f"Error getting HTTPS version on port {port}: {e}")
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
    except socket.timeout:
        logging.error(f"RTSP version check timed out on port {port}")
    except Exception as e:
        logging.error(f"Error getting RTSP version on port {port}: {e}")
    return None

def check_host_up(ip):
    try:
        output = subprocess.check_output(['ping', '-c', '10', ip], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    ip = get_ip_from_user()
    start_port = 1
    end_port = 10000
    
    cores = 6
    cores = psutil.cpu_count(logical=True)
    print(f"number of cores in the cpu: {cores}")
    threads = cores

    if(check_host_up(ip)):
        print("host is up : scanning.........")
    else:
        print("host is down :/")
        return 

    st = time.time()
    print(f"Scanning {ip} from port {start_port} to {end_port}...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    print(result)
            except Exception as e:
                logging.error(f"Error in thread: {e}")
    
    end = time.time()
    duration = end - st 
    print(f"Duration of scanning is {duration:.2f} seconds")

if __name__ == "__main__":
    main()

