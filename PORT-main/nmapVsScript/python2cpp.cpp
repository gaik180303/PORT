#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <regex>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
using namespace std;

std::map<int, std::string> parse_nmap_services(const std::string &file_path) {
    std::map<int, std::string> services;
    std::ifstream file(file_path);
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t space_pos = line.find(' ');
        if (space_pos != std::string::npos) {
            std::string service_name = line.substr(0, space_pos);
            std::string port_proto = line.substr(space_pos + 1);
            size_t slash_pos = port_proto.find('/');
            if (slash_pos != std::string::npos) {
                int port = std::stoi(port_proto.substr(0, slash_pos));
                services[port] = service_name;
            }
        }
    }
    return services;
}

bool is_valid_ip(const std::string &ip) {
    std::regex pattern(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    return std::regex_match(ip, pattern);
}

std::string get_ip_from_user(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <IP_ADDRESS>" << std::endl;
        exit(1);
    }
    return std::string(argv[1]);
}

std::vector<int> scan_ports(const std::string &ip, int start_port, int end_port) {
    std::vector<int> open_ports;
    for (int port = start_port; port <= end_port; ++port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            open_ports.push_back(port);
        }
        close(sock);
    }
    return open_ports;
}

std::string get_banner(const std::string &ip, int port) {
    std::string banner;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return banner;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        const char *msg = "\n";
        send(sock, msg, strlen(msg), 0);
        char buffer[1024] = {0};
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            banner = std::string(buffer, bytes_received);
        }
    }
    close(sock);
    return banner;
}

std::string get_http_version(const std::string &ip, int port) {
    std::string version;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return version;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string request = "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n";
        send(sock, request.c_str(), request.length(), 0);
        char buffer[1024] = {0};
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            version = std::string(buffer, bytes_received);
            size_t end_of_first_line = version.find('\r');
            if (end_of_first_line != std::string::npos) {
                version = version.substr(0, end_of_first_line);
            }
        }
    }
    close(sock);
    return version;
}

std::string get_https_version(const std::string &ip, int port) {
    std::string version;
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) return version;

    SSL *ssl = SSL_new(ctx);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return version;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) == 1) {
            std::string request = "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n";
            SSL_write(ssl, request.c_str(), request.length());
            char buffer[1024] = {0};
            int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_received > 0) {
                version = std::string(buffer, bytes_received);
                size_t end_of_first_line = version.find('\r');
                if (end_of_first_line != std::string::npos) {
                    version = version.substr(0, end_of_first_line);
                }
            }
        }
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return version;
}

std::string get_rtsp_version(const std::string &ip, int port) {
    std::string version;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return version;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        std::string request = "OPTIONS rtsp://" + ip + ":554 RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        send(sock, request.c_str(), request.length(), 0);
        char buffer[1024] = {0};
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0) {
            version = std::string(buffer, bytes_received);
            size_t end_of_first_line = version.find('\r');
            if (end_of_first_line != std::string::npos) {
                version = version.substr(0, end_of_first_line);
            }
        }
    }
    close(sock);
    return version;
}

int main(int argc, char *argv[]) {
    std::string ip = get_ip_from_user(argc, argv);
    int start_port = 1;
    int end_port = 10000;
    
    auto start = std::chrono::high_resolution_clock::now();
    std::cout << "Scanning " << ip << " from port " << start_port << " to " << end_port << "..." << std::endl;
    
    auto open_ports = scan_ports(ip, start_port, end_port);
    
    if (open_ports.empty()) {
        std::cout << "All ports are closed." << std::endl;
        return 0;
    }
    
    auto nmap_services = parse_nmap_services("nmap-services");

    std::cout << "PORT     STATE SERVICE VERSION" << std::endl;
    for (int port : open_ports) {
        std::string service_name = nmap_services.count(port) ? nmap_services[port] : "unknown";
        std::string version;
        
        if (port == 80) {
            version = get_http_version(ip, port);
        } else if (port == 443) {
            version = get_https_version(ip, port);
        } else if (port == 554) {
            version = get_rtsp_version(ip, port);
        }
        
        if (!version.empty()) {
            std::cout << port << "/tcp   open  " << service_name << " " << version << std::endl;
        } else {
            std::string banner = get_banner(ip, port);
            if (!banner.empty()) {
                std::cout << port << "/tcp   open  " << service_name << " " << banner << std::endl;
            } else {
                std::cout << port << "/tcp   open  " << service_name << std::endl;
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    //std::cout << "Duration : "<< duration<< endl;
  return 0;
}
