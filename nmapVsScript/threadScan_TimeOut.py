import socket
import re
import ssl
import sys
import subprocess
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

# add all ports are closed condition

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
port = []
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
            else:
                port.append(port)
                #print(f"port closed {port}")
    except:
        pass

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
        pass
    return None

def get_http_version(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
            response = s.recv(1024).decode()
            version_line = response.split('\r\n')[0]
            version = version_line.split()[0]
            return version
    except:
        pass
    return None

def get_https_version(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.settimeout(1)
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
                response = ssock.recv(1024).decode()
                version_line = response.split('\r\n')[0]
                version = version_line.split()[0]
                return version
    except:
        pass
    return None

def get_rtsp_version(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            request = f"OPTIONS rtsp://{ip}:554 RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            s.send(request.encode())
            response = s.recv(1024).decode()
            version_line = response.split('\r\n')[0]
            version = version_line.split()[0]
            return version
    except:
        pass
    return None

def check_host_up(ip):
    try:
        output = subprocess.check_output(['ping', '-c', '10', ip], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def main_scan():
    ip = get_ip_from_user()
    start_port = 1
    end_port = 10000
    
    cores = psutil.cpu_count(logical=True)
    #print(f"Number of cores in the CPU: {cores}")
    threads = cores

    if check_host_up(ip):
        pass
        #print("Host is up: scanning...")
    else:
        print("Host is down :/")
        return 

    st = time.time()
    #print(f"Scanning {ip} from port {start_port} to {end_port}...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    print(result)
            except:
                pass
    
    if len(port) == 10000:
        print("all ports are closed")
    end = time.time()
    duration = end - st 
    #print(f"Duration of scanning: {duration:.2f} seconds")


def main():
    # Set up a process for scanning
    scan_process = multiprocessing.Process(target=main_scan)

    # Start the scanning process
    scan_process.start()

    # Join the process and set a timeout of 60 seconds
    scan_process.join(timeout=60)

    # If the scan_process is still alive after the timeout, terminate it
    if scan_process.is_alive():
        print("Scan timed out after 60 seconds!")
        scan_process.terminate()
        scan_process.join()

if __name__ == "__main__":
    main()

