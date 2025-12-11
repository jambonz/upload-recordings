// s3-client-manager.cpp
#include "s3-client-manager.h"
#include <cstdlib>
#include <sstream>
#include <algorithm>

// Static member initialization
std::vector<std::string> S3ClientManager::pathStyleServices_;

void S3ClientManager::initPathStyleServices() {
    const char* envValue = std::getenv("S3_PATH_STYLE_SERVICES");
    if (envValue != nullptr && envValue[0] != '\0') {
        std::string services(envValue);
        std::stringstream ss(services);
        std::string service;
        while (std::getline(ss, service, ',')) {
            // Trim whitespace
            service.erase(0, service.find_first_not_of(" \t"));
            service.erase(service.find_last_not_of(" \t") + 1);
            if (!service.empty()) {
                pathStyleServices_.push_back(service);
                spdlog::info("S3ClientManager: Added '{}' to path-style services list", service);
            }
        }
    }
}

std::shared_ptr<Aws::S3Crt::S3CrtClient> S3ClientManager::getClient(
    const Aws::Auth::AWSCredentials& credentials,
    const Aws::String& region,
    const Aws::String& customEndpoint,
    int maxConnections
) {
    ClientKey key{
        std::string(region.c_str()),
        std::string(customEndpoint.c_str()),
        std::string(credentials.GetAWSAccessKeyId().c_str())
    };

    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = clients_.find(key);
    if (it != clients_.end()) {
        spdlog::info("Reusing existing S3 client for region: {}, endpoint: {}, accessKey: {}...", 
                     region.c_str(), 
                     customEndpoint.empty() ? "default" : customEndpoint.c_str(),
                     std::string(credentials.GetAWSAccessKeyId().c_str()).substr(0, 8));
        return it->second;
    }

    // Create new client
    spdlog::info("Creating new shared S3 client for region: {}, endpoint: {}, accessKey: {}..., maxConnections: {}", 
                 region.c_str(), 
                 customEndpoint.empty() ? "default" : customEndpoint.c_str(),
                 std::string(credentials.GetAWSAccessKeyId().c_str()).substr(0, 8),
                 maxConnections);
    
    auto config = createConfig(region, customEndpoint, maxConnections);
    
    auto client = std::make_shared<Aws::S3Crt::S3CrtClient>(
        Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("S3ClientManager", credentials),
        config
    );
    
    clients_[key] = client;
    
    spdlog::info("S3ClientManager now managing {} unique clients", clients_.size());
    
    return client;
}

Aws::S3Crt::ClientConfiguration S3ClientManager::createConfig(
    const Aws::String& region,
    const Aws::String& customEndpoint,
    int maxConnections
) {
    Aws::S3Crt::ClientConfiguration config;
    config.region = region;
    config.maxConnections = maxConnections;  // This is shared across all sessions using this client
    
    // Connection settings
    config.connectTimeoutMs = 3000;  // 3 seconds
    config.requestTimeoutMs = 30000; // 30 seconds
    config.enableTcpKeepAlive = true;
    config.tcpKeepAliveIntervalMs = 30000;
    
    // Retry strategy
    config.retryStrategy = Aws::MakeShared<Aws::Client::StandardRetryStrategy>("S3CrtClient", 3);
    
    // S3 compatibility settings
    config.scheme = Aws::Http::Scheme::HTTPS;
    config.verifySSL = true;
    config.followRedirects = Aws::Client::FollowRedirectsPolicy::ALWAYS;
    config.enableEndpointDiscovery = false;

    if (!customEndpoint.empty()) {
        std::string endpoint = customEndpoint;
        
        // Clean up endpoint URL
        if (endpoint.back() == '/') {
            endpoint.pop_back();
        }
        
        // Remove protocol prefix if present
        if (endpoint.find("https://") == 0) {
            endpoint = endpoint.substr(8);
        } else if (endpoint.find("http://") == 0) {
            endpoint = endpoint.substr(7);
        }
        
        config.endpointOverride = endpoint;
        
        // Determine virtual addressing based on endpoint
        bool useVirtualAddressing = true;

        // Always use path-style for localhost
        if (endpoint.find("localhost") != std::string::npos ||
            endpoint.find("127.0.0.1") != std::string::npos) {
            useVirtualAddressing = false;
        }

        // Check against user-configured path-style services (from S3_PATH_STYLE_SERVICES env var)
        if (useVirtualAddressing) {
            for (const auto& service : pathStyleServices_) {
                if (endpoint.find(service) != std::string::npos) {
                    useVirtualAddressing = false;
                    spdlog::info("Using path-style addressing for endpoint '{}' (matched '{}')", endpoint, service);
                    break;
                }
            }
        }

        config.useVirtualAddressing = useVirtualAddressing;
    }

    return config;
}

size_t S3ClientManager::getClientCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return clients_.size();
}

void S3ClientManager::logClientStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    spdlog::info("S3ClientManager stats: {} unique clients created", clients_.size());
    
    int i = 1;
    for (const auto& [key, client] : clients_) {
        spdlog::info("  Client {}: region={}, endpoint={}, accessKey={}...", 
                     i++,
                     key.region,
                     key.endpoint.empty() ? "default" : key.endpoint,
                     key.accessKey.substr(0, 8));
    }
}

void S3ClientManager::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    spdlog::info("Shutting down S3ClientManager with {} clients", clients_.size());
    clients_.clear();
}