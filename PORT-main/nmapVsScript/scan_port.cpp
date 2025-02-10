#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>

#define TIMEOUT 1 // Timeout in seconds
using namespace std;
  
// Common ports and their services
map<int, string> common_ports = {
    {80, "http"},
    {443, "https"},
    {22, "ssh"},
    {21, "ftp"},
    {23, "telnet"},
    {25, "smtp"},
    {110, "pop3"},
    {143, "imap"},
    {53, "dns"},
    {3306, "mysql"},
    {3389, "ms-wbt-server"},
    {554, "rtsp"}
};

// Parse nmap-services file
map<int, string> parse_nmap_services(const string& file_path) {
    map<int, string> services;
    FILE* file = fopen(file_path.c_str(), "r");
    if (file) {
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            int port;
            char service_name[128];
            char port_proto[128];
            if (sscanf(line, "%127s %127s", service_name, port_proto) == 2) {
                if (sscanf(port_proto, "%d/", &port) == 1) {
                    services[port] = service_name;
                }
            }
        }
        fclose(file);
    }
    return services;
}

// Get service name from port number
string get_service_name(int port, const map<int, string>& nmap_services) {
    auto it = common_ports.find(port);
    if (it != common_ports.end()) {
        return it->second;
    }
    auto nmap_it = nmap_services.find(port);
    if (nmap_it != nmap_services.end()) {
        return nmap_it->second;
    }
    return "unknown";
}

void scan_port_and_get_banner(const string& ip, int port, vector<pair<int, string>>& results) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        char banner[1024];
        ssize_t len = recv(sockfd, banner, sizeof(banner) - 1, 0);
        if (len > 0) {
            banner[len] = '\0';
            results.emplace_back(port, string(banner));
        } else {
            results.emplace_back(port, "No banner");
        }
    }

    close(sockfd);
}

int main(int argc, char* argv[]) {
    map<int, string> nmap_services = parse_nmap_services("nmap-services");
    cout<<"scanning ...."<<endl;
    string ip = argv[1];
    //cout << "Enter the target IP address: ";
    //cin>>ip;

    int start_port = 1;
    int end_port = 10000;

    vector<pair<int, string>> open_ports;

    vector<thread> threads;


    
    auto start_time = chrono::high_resolution_clock::now();

    for (int port = start_port; port <= end_port; ++port) {
        threads.emplace_back(scan_port_and_get_banner, ip, port, ref(open_ports));
        if (threads.size() >= 100) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }

    for (auto& t : threads) t.join();

    auto end_time = chrono::high_resolution_clock::now();



    chrono::duration<double> duration = end_time - start_time;
    cout << "Scanning completed in " << duration.count() << " seconds." << std::endl;

    if (open_ports.empty()) {
        cout << "All ports are closed or the host is unreachable." << endl;
    } else {
        cout << "PORT     STATE SERVICE VERSION" << endl;
        for (const auto& [port, banner] : open_ports) {
            string service_name = get_service_name(port, nmap_services);
            cout << port << "/tcp   open  " << service_name << " " << banner << endl;
        }
    }

    return 0;
}
