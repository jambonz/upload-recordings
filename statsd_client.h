#ifndef STATSD_CLIENT_H
#define STATSD_CLIENT_H

#include <string>
#include <sstream>
#include <random>
#include <chrono>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class StatsdClient {
private:
    std::string host_;
    int port_;
    std::string prefix_;
    int socket_fd_;
    struct sockaddr_in server_addr_;
    std::mt19937 rng_;
    std::uniform_real_distribution<double> dist_;
    
    void send(const std::string& data) {
        if (socket_fd_ < 0) return;
        
        sendto(socket_fd_, data.c_str(), data.length(), 0,
               (struct sockaddr*)&server_addr_, sizeof(server_addr_));
    }
    
    std::string format_metric(const std::string& key, const std::string& value, 
                             const std::string& type, double sample_rate = 1.0) {
        std::ostringstream oss;
        
        if (!prefix_.empty()) {
            oss << prefix_ << ".";
        }
        oss << key << ":" << value << "|" << type;
        
        if (sample_rate < 1.0) {
            oss << "|@" << sample_rate;
        }
        
        return oss.str();
    }
    
    bool should_send(double sample_rate) {
        if (sample_rate >= 1.0) return true;
        return dist_(rng_) < sample_rate;
    }

public:
    StatsdClient(const std::string& host = "127.0.0.1", 
                 int port = 8125, 
                 const std::string& prefix = "")
        : host_(host), port_(port), prefix_(prefix), socket_fd_(-1),
          rng_(std::chrono::steady_clock::now().time_since_epoch().count()),
          dist_(0.0, 1.0) {
        
#ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
        
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }
        
        memset(&server_addr_, 0, sizeof(server_addr_));
        server_addr_.sin_family = AF_INET;
        server_addr_.sin_port = htons(port_);
        
        if (inet_pton(AF_INET, host_.c_str(), &server_addr_.sin_addr) <= 0) {
            close_socket();
            throw std::runtime_error("Invalid address: " + host_);
        }
    }
    
    ~StatsdClient() {
        close_socket();
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    void close_socket() {
        if (socket_fd_ >= 0) {
#ifdef _WIN32
            closesocket(socket_fd_);
#else
            close(socket_fd_);
#endif
            socket_fd_ = -1;
        }
    }
    
    // Counter - increment/decrement a counter
    void count(const std::string& key, int value = 1, double sample_rate = 1.0) {
        if (!should_send(sample_rate)) return;
        
        std::string metric = format_metric(key, std::to_string(value), "c", sample_rate);
        send(metric);
    }
    
    // Increment helper
    void increment(const std::string& key, double sample_rate = 1.0) {
        count(key, 1, sample_rate);
    }
    
    // Decrement helper
    void decrement(const std::string& key, double sample_rate = 1.0) {
        count(key, -1, sample_rate);
    }
    
    // Timer - record time in milliseconds
    void timing(const std::string& key, double ms, double sample_rate = 1.0) {
        if (!should_send(sample_rate)) return;
        
        std::string metric = format_metric(key, std::to_string(static_cast<int>(ms)), "ms", sample_rate);
        send(metric);
    }
    
    // Gauge - record an arbitrary value
    void gauge(const std::string& key, double value, double sample_rate = 1.0) {
        if (!should_send(sample_rate)) return;
        
        std::string metric = format_metric(key, std::to_string(value), "g", sample_rate);
        send(metric);
    }
    
    // Set - record unique occurrences
    void set(const std::string& key, const std::string& value, double sample_rate = 1.0) {
        if (!should_send(sample_rate)) return;
        
        std::string metric = format_metric(key, value, "s", sample_rate);
        send(metric);
    }
    
    // Histogram - for recording distributions (extension supported by some StatsD implementations)
    void histogram(const std::string& key, double value, double sample_rate = 1.0) {
        if (!should_send(sample_rate)) return;
        
        std::string metric = format_metric(key, std::to_string(value), "h", sample_rate);
        send(metric);
    }
    
    // Timer helper class for automatic timing
    class Timer {
    private:
        StatsdClient& client_;
        std::string key_;
        double sample_rate_;
        std::chrono::high_resolution_clock::time_point start_;
        
    public:
        Timer(StatsdClient& client, const std::string& key, double sample_rate = 1.0)
            : client_(client), key_(key), sample_rate_(sample_rate),
              start_(std::chrono::high_resolution_clock::now()) {}
        
        ~Timer() {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_);
            client_.timing(key_, duration.count(), sample_rate_);
        }
    };
    
    // Create a timer that automatically sends timing data when destroyed
    Timer timer(const std::string& key, double sample_rate = 1.0) {
        return Timer(*this, key, sample_rate);
    }
};

#endif // STATSD_CLIENT_H