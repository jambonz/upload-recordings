#ifndef CLOUDWATCH_CLIENT_H
#define CLOUDWATCH_CLIENT_H

#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <sstream>
#include <aws/core/Aws.h>
#include <aws/monitoring/CloudWatchClient.h>
#include <aws/monitoring/model/PutMetricDataRequest.h>
#include <aws/monitoring/model/MetricDatum.h>
#include <aws/monitoring/model/Dimension.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/http/HttpClient.h>
#include <aws/core/http/HttpRequest.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/stream/ResponseStream.h>
#include <spdlog/spdlog.h>

class CloudWatchClient {
public:
    // Singleton pattern
    static CloudWatchClient& getInstance() {
        static CloudWatchClient instance;
        return instance;
    }

    // Initialize CloudWatch client - call this at application startup
    void initialize();

    // Start the periodic metrics publishing thread
    void startMetricsPublishing();

    // Stop the periodic metrics publishing thread
    void stopMetricsPublishing();

    // Check if CloudWatch is available and enabled
    bool isEnabled() const {
        return enabled_;
    }

    // Set callback to get current session count
    void setSessionCountCallback(std::function<size_t()> callback) {
        sessionCountCallback_ = callback;
    }

private:
    CloudWatchClient() : enabled_(false), stopPublishing_(false) {}
    ~CloudWatchClient() {
        stopMetricsPublishing();
    }
    
    // Deleted copy/move constructors and assignment operators
    CloudWatchClient(const CloudWatchClient&) = delete;
    CloudWatchClient& operator=(const CloudWatchClient&) = delete;
    CloudWatchClient(CloudWatchClient&&) = delete;
    CloudWatchClient& operator=(CloudWatchClient&&) = delete;

    // Check if running on EC2 instance
    bool isRunningOnEC2();

    // Check if EC2 instance has IAM role with CloudWatch permissions
    bool hasCloudWatchPermissions();

    // Get EC2 instance metadata
    std::string getInstanceMetadata(const std::string& path);

    // Publish metrics to CloudWatch
    void publishMetrics();

    // Metrics publishing thread function
    void metricsPublishingThread();

    std::unique_ptr<Aws::CloudWatch::CloudWatchClient> cloudWatchClient_;
    std::function<size_t()> sessionCountCallback_;
    std::thread publishingThread_;
    std::atomic<bool> enabled_;
    std::atomic<bool> stopPublishing_;
    std::string instanceId_;
    std::string instanceType_;
    std::string availabilityZone_;
};

// Implementation

inline void CloudWatchClient::initialize() {
    spdlog::info("Initializing CloudWatch client...");
    
    // Check if we're running on EC2
    if (!isRunningOnEC2()) {
        spdlog::info("Not running on EC2, CloudWatch metrics disabled");
        return;
    }
    
    // Check if we have CloudWatch permissions
    if (!hasCloudWatchPermissions()) {
        spdlog::warn("No CloudWatch permissions available, metrics disabled");
        return;
    }
    
    // Initialize CloudWatch client
    Aws::Client::ClientConfiguration config;
    cloudWatchClient_ = std::make_unique<Aws::CloudWatch::CloudWatchClient>(config);
    
    enabled_ = true;
    spdlog::info("CloudWatch client initialized successfully");
}

inline void CloudWatchClient::startMetricsPublishing() {
    if (!enabled_) {
        return;
    }
    
    stopPublishing_ = false;
    publishingThread_ = std::thread(&CloudWatchClient::metricsPublishingThread, this);
    spdlog::info("Started CloudWatch metrics publishing thread");
}

inline void CloudWatchClient::stopMetricsPublishing() {
    if (publishingThread_.joinable()) {
        stopPublishing_ = true;
        publishingThread_.join();
        spdlog::info("Stopped CloudWatch metrics publishing thread");
    }
}

inline bool CloudWatchClient::isRunningOnEC2() {
    spdlog::debug("Checking if running on EC2...");
    
    // Try to access EC2 instance metadata service
    std::string tokenResponse = getInstanceMetadata("/latest/api/token");
    if (tokenResponse.empty()) {
        spdlog::debug("Failed to get IMDSv2 token");
        return false;
    }
    
    // Get instance ID to confirm we're on EC2
    instanceId_ = getInstanceMetadata("/latest/meta-data/instance-id");
    if (instanceId_.empty()) {
        spdlog::debug("Failed to get instance ID");
        return false;
    }
    
    // Get additional instance metadata
    instanceType_ = getInstanceMetadata("/latest/meta-data/instance-type");
    availabilityZone_ = getInstanceMetadata("/latest/meta-data/placement/availability-zone");
    
    spdlog::info("Detected EC2 instance: {} ({})", instanceId_, instanceType_);
    return true;
}

inline bool CloudWatchClient::hasCloudWatchPermissions() {
    // Try to create a simple CloudWatch client and test permissions
    try {
        Aws::Client::ClientConfiguration config;
        
        // If we're on EC2, try to get the region from metadata
        if (!instanceId_.empty()) {
            std::string region = getInstanceMetadata("/latest/meta-data/placement/region");
            if (!region.empty()) {
                config.region = region;
                spdlog::debug("Using region from EC2 metadata: {}", region);
            }
        }
        
        // Check if we have any form of AWS credentials available
        auto credentialsProvider = Aws::Auth::DefaultAWSCredentialsProviderChain();
        auto credentials = credentialsProvider.GetAWSCredentials();
        
        if (credentials.GetAWSAccessKeyId().empty()) {
            spdlog::warn("No AWS credentials found (no IAM role, environment variables, or credential files)");
            return false;
        }
        
        spdlog::debug("Found AWS credentials, testing CloudWatch access...");
        
        auto testClient = std::make_unique<Aws::CloudWatch::CloudWatchClient>(config);
        
        // Create a test metric request to verify permissions
        Aws::CloudWatch::Model::PutMetricDataRequest request;
        request.SetNamespace("JambonzTest");
        
        Aws::CloudWatch::Model::MetricDatum datum;
        datum.SetMetricName("PermissionTest");
        datum.SetValue(0.0);
        datum.SetTimestamp(Aws::Utils::DateTime::Now());
        
        request.AddMetricData(datum);
        
        // Make the request
        auto outcome = testClient->PutMetricData(request);
        
        if (outcome.IsSuccess()) {
            spdlog::info("CloudWatch permissions verified successfully");
            return true;
        } else {
            spdlog::warn("CloudWatch permission test failed: {}", outcome.GetError().GetMessage());
            return false;
        }
    } catch (const std::exception& e) {
        spdlog::warn("Exception testing CloudWatch permissions: {}", e.what());
        return false;
    }
}

inline std::string CloudWatchClient::getInstanceMetadata(const std::string& path) {
    try {
        auto httpClient = Aws::Http::CreateHttpClient(Aws::Client::ClientConfiguration());
        
        // First get a token for IMDSv2
        auto tokenRequest = Aws::Http::CreateHttpRequest(
            Aws::String("http://169.254.169.254/latest/api/token"),
            Aws::Http::HttpMethod::HTTP_PUT,
            Aws::Utils::Stream::DefaultResponseStreamFactoryMethod
        );
        tokenRequest->SetHeaderValue("X-aws-ec2-metadata-token-ttl-seconds", "21600");
        
        auto tokenResponse = httpClient->MakeRequest(tokenRequest);
        if (tokenResponse->GetResponseCode() != Aws::Http::HttpResponseCode::OK) {
            return "";
        }
        
        // Get the token
        std::string token;
        std::istream& tokenStream = tokenResponse->GetResponseBody();
        std::ostringstream tokenBuffer;
        tokenBuffer << tokenStream.rdbuf();
        token = tokenBuffer.str();
        
        // Now make the metadata request with the token
        auto metadataRequest = Aws::Http::CreateHttpRequest(
            Aws::String("http://169.254.169.254") + path.c_str(),
            Aws::Http::HttpMethod::HTTP_GET,
            Aws::Utils::Stream::DefaultResponseStreamFactoryMethod
        );
        metadataRequest->SetHeaderValue("X-aws-ec2-metadata-token", token);
        
        auto metadataResponse = httpClient->MakeRequest(metadataRequest);
        if (metadataResponse->GetResponseCode() != Aws::Http::HttpResponseCode::OK) {
            return "";
        }
        
        std::string result;
        std::istream& responseStream = metadataResponse->GetResponseBody();
        std::ostringstream resultBuffer;
        resultBuffer << responseStream.rdbuf();
        result = resultBuffer.str();
        
        return result;
    } catch (const std::exception& e) {
        spdlog::debug("Exception getting instance metadata: {}", e.what());
        return "";
    }
}

inline void CloudWatchClient::publishMetrics() {
    if (!enabled_ || !sessionCountCallback_) {
        return;
    }
    
    try {
        size_t sessionCount = sessionCountCallback_();
        
        Aws::CloudWatch::Model::PutMetricDataRequest request;
        request.SetNamespace("Jambonz/Recording");
        
        Aws::CloudWatch::Model::MetricDatum datum;
        datum.SetMetricName("RecordingSessionCount");
        datum.SetValue(static_cast<double>(sessionCount));
        datum.SetTimestamp(Aws::Utils::DateTime::Now());
        
        // Add dimensions for better metric organization
        Aws::CloudWatch::Model::Dimension instanceDimension;
        instanceDimension.SetName("InstanceId");
        instanceDimension.SetValue(instanceId_);
        datum.AddDimensions(instanceDimension);
        
        if (!instanceType_.empty()) {
            Aws::CloudWatch::Model::Dimension typeDimension;
            typeDimension.SetName("InstanceType");
            typeDimension.SetValue(instanceType_);
            datum.AddDimensions(typeDimension);
        }
        
        if (!availabilityZone_.empty()) {
            Aws::CloudWatch::Model::Dimension azDimension;
            azDimension.SetName("AvailabilityZone");
            azDimension.SetValue(availabilityZone_);
            datum.AddDimensions(azDimension);
        }
        
        request.AddMetricData(datum);
        
        auto outcome = cloudWatchClient_->PutMetricData(request);
        
        if (outcome.IsSuccess()) {
            spdlog::debug("Published CloudWatch metric: RecordingSessionCount = {}", sessionCount);
        } else {
            spdlog::error("Failed to publish CloudWatch metric: {}", outcome.GetError().GetMessage());
        }
    } catch (const std::exception& e) {
        spdlog::error("Exception publishing CloudWatch metrics: {}", e.what());
    }
}

inline void CloudWatchClient::metricsPublishingThread() {
    while (!stopPublishing_) {
        publishMetrics();
        
        // Sleep for 30 seconds, but check for stop signal every second
        for (int i = 0; i < 30 && !stopPublishing_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

#endif // CLOUDWATCH_CLIENT_H