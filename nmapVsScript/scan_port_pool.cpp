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
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>

#define TIMEOUT 1 // Timeout in seconds
using namespace std;

class ThreadPool {
public:
    ThreadPool(size_t threads);
    ~ThreadPool();

    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> future<typename result_of<F(Args...)>::type>;

private:
    vector<thread> workers;
    queue<function<void()>> tasks;
    
    mutex queue_mutex;
    condition_variable condition;
    bool stop;
};

ThreadPool::ThreadPool(size_t threads) : stop(false) {
    for (size_t i = 0; i < threads; ++i)
        workers.emplace_back(
            [this] {
                for (;;) {
                    function<void()> task;
                    {
                        unique_lock<mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this]{ return this->stop || !this->tasks.empty(); });
                        if (this->stop && this->tasks.empty())
                            return;
                        task = move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            }
        );
}

ThreadPool::~ThreadPool() {
    {
        unique_lock<mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    for (thread &worker: workers)
        worker.join();
}

template<class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> future<typename result_of<F(Args...)>::type> {
    using return_type = typename result_of<F(Args...)>::type;

    auto task = make_shared<packaged_task<return_type()>>(
        bind(forward<F>(f), forward<Args>(args)...)
    );

    future<return_type> res = task->get_future();
    {
        unique_lock<mutex> lock(queue_mutex);

        if (stop)
            throw runtime_error("enqueue on stopped ThreadPool");

        tasks.emplace([task](){ (*task)(); });
    }
    condition.notify_one();
    return res;
}

void scan_port_and_get_banner(const string& ip, int port, vector<pair<int, string>>& results, mutex& results_mutex) {
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
            lock_guard<mutex> lock(results_mutex);
            results.emplace_back(port, string(banner));
        } else {
            lock_guard<mutex> lock(results_mutex);
            results.emplace_back(port, "No banner");
        }
    }

    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <IP>" << endl;
        return 1;
    }
      
    string ip = argv[1];
    int start_port = 1;
    int end_port = 10000;

    vector<pair<int, string>> open_ports;
    mutex results_mutex;

    ThreadPool pool(100); // Adjust the number of threads as needed

    auto start_time = chrono::high_resolution_clock::now();

    vector<future<void>> futures;
    for (int port = start_port; port <= end_port; ++port) {
        futures.emplace_back(
            pool.enqueue(scan_port_and_get_banner, ip, port, ref(open_ports), ref(results_mutex))
        );
    }

    for (auto &fut : futures) {
        fut.get();
    }

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end_time - start_time;
    cout << "Scanning completed in " << duration.count() << " seconds." << endl;

    if (open_ports.empty()) {
        cout << "All ports are closed or the host is unreachable." << endl;
    } else {
        cout << "PORT     STATE SERVICE VERSION" << endl;
        for (const auto& [port, banner] : open_ports) {
            cout << port << "/tcp   open  " << "Service Name: " << banner << endl;
        }
    }

    return 0;
}

