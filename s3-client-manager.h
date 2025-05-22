// s3-client-manager.h
#ifndef S3_CLIENT_MANAGER_H
#define S3_CLIENT_MANAGER_H

#include <aws/s3-crt/S3CrtClient.h>
#include <aws/core/auth/AWSCredentials.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <string>
#include <spdlog/spdlog.h>

class S3ClientManager {
public:
    // Singleton pattern
    static S3ClientManager& getInstance() {
        static S3ClientManager instance;
        return instance;
    }

    // Get or create a shared S3 client for given parameters
    std::shared_ptr<Aws::S3Crt::S3CrtClient> getClient(
        const Aws::Auth::AWSCredentials& credentials,
        const Aws::String& region,
        const Aws::String& customEndpoint = "",
        int maxConnections = 150
    );

    // Get statistics about client usage
    size_t getClientCount() const;
    void logClientStats() const;

    // Shutdown all clients (called during app shutdown)
    void shutdown();

private:
    S3ClientManager() = default;
    ~S3ClientManager() { shutdown(); }
    
    // Deleted copy/move constructors
    S3ClientManager(const S3ClientManager&) = delete;
    S3ClientManager& operator=(const S3ClientManager&) = delete;
    S3ClientManager(S3ClientManager&&) = delete;
    S3ClientManager& operator=(S3ClientManager&&) = delete;

    struct ClientKey {
        std::string region;
        std::string endpoint;
        std::string accessKey;
        
        bool operator==(const ClientKey& other) const {
            return region == other.region && 
                   endpoint == other.endpoint && 
                   accessKey == other.accessKey;
        }
    };

    struct ClientKeyHash {
        std::size_t operator()(const ClientKey& key) const {
            return std::hash<std::string>{}(key.region + key.endpoint + key.accessKey);
        }
    };

    mutable std::mutex mutex_;
    std::unordered_map<ClientKey, std::shared_ptr<Aws::S3Crt::S3CrtClient>, ClientKeyHash> clients_;
    
    // Helper to create client configuration
    Aws::S3Crt::ClientConfiguration createConfig(
        const Aws::String& region,
        const Aws::String& customEndpoint,
        int maxConnections
    );
};

#endif // S3_CLIENT_MANAGER_H