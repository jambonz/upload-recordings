#include <iostream>
#include <stdexcept>
#include <fstream>
#include <cstdio>
#include "s3-compatible-uploader.h"
#include "wav-header.h"
#include "string-utils.h"
#include "config.h"

constexpr int UPLOAD_TIMEOUT_SECONDS = 300; // 5 minutes timeout

S3CompatibleUploader::S3CompatibleUploader(const std::shared_ptr<Session>& session, 
    std::shared_ptr<spdlog::logger> log,
    std::string& uploadFolder,
    RecordFileType ftype,
    const Aws::Auth::AWSCredentials& credentials,
    const Aws::String& region,
    const Aws::String& bucketName,
    const Aws::String& customEndpoint)
    : StorageUploader(session), bucketName_(bucketName), region_(region), recordFileType_(ftype) {
    Aws::S3Crt::ClientConfiguration config;
    config.region = region;
    config.maxConnections = Config::getInstance().getAwsMaxConnections();
    
    // Add connection settings
    config.connectTimeoutMs = 3000;  // 3 seconds
    config.requestTimeoutMs = 30000; // 30 seconds
    config.enableTcpKeepAlive = true;
    config.tcpKeepAliveIntervalMs = 30000;
    
    // Use standard retry strategy
    config.retryStrategy = Aws::MakeShared<Aws::Client::StandardRetryStrategy>("S3CrtClient", 3);

    // Additional settings for S3 compatibility
    config.scheme = Aws::Http::Scheme::HTTPS;
    config.verifySSL = true;
    config.followRedirects = Aws::Client::FollowRedirectsPolicy::ALWAYS;
    config.enableEndpointDiscovery = false;

    setLogger(log);

    if (!customEndpoint.empty()) {
        // Construct the proper endpoint URL
        std::string endpoint = customEndpoint;
        if (endpoint.back() == '/') {
            endpoint.pop_back();
        }
        
        // Remove any protocol prefix if present
        if (endpoint.find("https://") == 0) {
            endpoint = endpoint.substr(8);
        } else if (endpoint.find("http://") == 0) {
            endpoint = endpoint.substr(7);
        }
        
        config.endpointOverride = endpoint;
        
        // Determine if we should use virtual addressing based on the endpoint
        // Some services like Hetzner require it, while others like MinIO don't
        bool useVirtualAddressing = true;
        
        // Check for known services that don't use virtual addressing
        if (endpoint.find("minio") != std::string::npos || 
            endpoint.find("localhost") != std::string::npos ||
            endpoint.find("127.0.0.1") != std::string::npos) {
            useVirtualAddressing = false;
        }
        
        config.useVirtualAddressing = useVirtualAddressing;
        
        log_->info("Creating S3 compatible uploader for bucket:{}, endpoint {} ", bucketName, endpoint);
    } else {
        log_->info("Creating S3 uploader for bucket: {} in region {}", bucketName, region);
    }

    s3CrtClient_ = std::make_shared<Aws::S3Crt::S3CrtClient>(
        Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("MemoryStreamAllocator", credentials),
        config
    );

    // Create a temporary file for buffering data
    createTempFile(uploadFolder);
}

S3CompatibleUploader::~S3CompatibleUploader() {
}

bool S3CompatibleUploader::upload(std::vector<char>& data, bool isFinalChunk) {
    if (!tempFile_.is_open()) {
      log_->error("Temporary file is not open. Upload failed.");
      upload_failed_ = true;
      return false;
    }

    // Write the data chunk to the temporary file
    tempFile_.write(data.data(), data.size());
    if (!tempFile_.good()) {
      if (tempFile_.fail()) {
          log_->error("Logical error occurred while writing data to temporary file.");
      }
      if (tempFile_.bad()) {
          log_->error("Critical I/O error occurred while writing data to temporary file.");
      }
      upload_failed_ = true;
      return false;
    }
    tempFile_.flush();

    log_->info("S3CompatibleUploader uploaded {} bytes to temporary file {}.", data.size(), tempFilePath_);

    if (isFinalChunk) {
        finalizeUpload();
    }

    return true;
}

void S3CompatibleUploader::finalizeUpload() {
    try {
        // Record start time
        auto startTime = std::chrono::steady_clock::now();
        
        objectKey_ = createObjectPath(metadata_.call_sid, recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");
        log_->info("Created object key: {} for upload", objectKey_);

        // Create a PutObjectRequest
        Aws::S3Crt::Model::PutObjectRequest putObjectRequest;
        putObjectRequest.SetBucket(bucketName_);
        putObjectRequest.SetKey(objectKey_);
        putObjectRequest.SetContentType("binary/octet-stream");

        Aws::Map<Aws::String, Aws::String> awsMetadata;
        awsMetadata["Account-Sid"] = metadata_.account_sid.c_str();
        awsMetadata["Call-Sid"] = metadata_.call_sid.c_str();
        awsMetadata["Direction"] = metadata_.direction.c_str();
        awsMetadata["From"] = metadata_.from.c_str();
        awsMetadata["To"] = metadata_.to.c_str();
        awsMetadata["Application-Sid"] = metadata_.application_sid.c_str();
        awsMetadata["Originating-Sip-Id"] = metadata_.originating_sip_id.c_str();
        awsMetadata["Originating-Sip-Trunk-Name"] = metadata_.originating_sip_trunk_name.c_str();
        awsMetadata["Sample-Rate"] = std::to_string(metadata_.sample_rate).c_str();

        putObjectRequest.SetMetadata(awsMetadata);

        // Close the file stream if it is still open
        if (tempFile_.is_open()) {
            tempFile_.close();
        }

        // if this is a WAV file, we need to prepend a wave header
        std::string finalFilePath = tempFilePath_;
        if (recordFileType_ == RecordFileType::WAV) {
            // Use mkstemp to generate a unique temporary file for the WAV file
            char wavTempFilePath[] = "/tmp/uploads/wavfile-XXXXXX"; // Template for unique file
            int wavTempFd = mkstemp(wavTempFilePath); // Creates the file and returns a file descriptor
            if (wavTempFd == -1) {
                log_->error("Failed to create unique WAV temporary file using mkstemp: {}", strerror(errno));
                upload_failed_ = true;
                cleanupTempFile();
                return;
            }

            // Open the file stream associated with the descriptor
            std::ofstream wavTempFile(wavTempFilePath, std::ios::binary);
            if (!wavTempFile) {
                log_->error("Failed to open WAV temporary file: {}", wavTempFilePath);
                close(wavTempFd); // Close the file descriptor
                upload_failed_ = true;
                cleanupTempFile();
                return;
            }

            // Calculate the size of the raw audio data
            auto audioDataSize = std::filesystem::file_size(tempFilePath_);

            // Generate the WAV header
            WavHeaderPrepender headerPrepender(8000, 2, 16); // Sample rate, channels, bit depth
            std::vector<char> wavHeader = headerPrepender.createHeader(static_cast<uint32_t>(audioDataSize));

            // Write the WAV header to the new temporary file
            wavTempFile.write(wavHeader.data(), wavHeader.size());
            if (!wavTempFile.good()) {
                log_->error("Failed to write WAV header to temporary file: {}", wavTempFilePath);
                close(wavTempFd); // Close the file descriptor
                upload_failed_ = true;
                cleanupTempFile();
                return;
            }

            // Append the raw audio data to the new temporary file
            std::ifstream rawAudioFile(tempFilePath_, std::ios::binary);
            if (!rawAudioFile) {
                log_->error("Failed to open raw audio temporary file: {}", tempFilePath_);
                close(wavTempFd); // Close the file descriptor
                upload_failed_ = true;
                return;
            }

            wavTempFile << rawAudioFile.rdbuf(); // Efficiently copy raw audio data
            wavTempFile.close();
            rawAudioFile.close();
            close(wavTempFd); // Close the descriptor after all writes

            // Update the final file path to point to the new WAV file
            finalFilePath = wavTempFilePath;
        }

        // Attach the file stream to the request body
        auto inputStream = Aws::MakeShared<Aws::FStream>("PutObjectBody", finalFilePath.c_str(), std::ios::in | std::ios::binary);
        if (!inputStream->good()) {
            // Retrieve specific error details
            std::string errorMessage;

            if ((inputStream->rdstate() & std::ios::failbit) != 0) {
                errorMessage += "Logical error on input/output operation. ";
            }
            if ((inputStream->rdstate() & std::ios::badbit) != 0) {
                errorMessage += "Read/write error on file stream. ";
            }
            if ((inputStream->rdstate() & std::ios::eofbit) != 0) {
                errorMessage += "End-of-File reached prematurely. ";
            }

            // Use errno to get a system-level error message
            errorMessage += std::strerror(errno);

            log_->error("Failed to open temporary file for upload: {}. Error: {}", tempFilePath_, errorMessage);
            upload_failed_ = true;
            cleanupTempFile();
            return;
        }
      
        putObjectRequest.SetBody(inputStream);

        // Create a shared pointer to store the final file path for cleanup in the callback
        auto finalFilePathPtr = std::make_shared<std::string>(finalFilePath);
        
        // Create a promise and future to track completion
        auto promise = std::make_shared<std::promise<void>>();
        auto future = promise->get_future();
        
        log_->info("Starting upload of file: {} to {}", tempFilePath_, objectKey_);
        
        s3CrtClient_->PutObjectAsync(putObjectRequest, 
            [this, finalFilePathPtr, promise, startTime](const Aws::S3Crt::S3CrtClient* client,
                                    const Aws::S3Crt::Model::PutObjectRequest& request,
                                    const Aws::S3Crt::Model::PutObjectOutcome& outcome,
                                    const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context) {
                try {
                    if (!outcome.IsSuccess()) {
                        const auto& error = outcome.GetError();
                        log_->error("Failed to upload file: {}: Error Type: {}, Error Message: {}, Request ID: {}", 
                            tempFilePath_, 
                            static_cast<int>(error.GetErrorType()),
                            error.GetMessage(),
                            error.GetRequestId());
                        upload_failed_ = true;
                    } else {
                        // Calculate upload duration
                        auto endTime = std::chrono::steady_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
                        log_->info("File uploaded successfully: {} to {} (took {} seconds)", 
                            tempFilePath_, objectKey_, duration);
                    }
                    
                    // Cleanup after upload completes
                    if (recordFileType_ == RecordFileType::WAV) {
                        std::remove(finalFilePathPtr->c_str());
                    }
                    cleanupTempFile();
                    
                    // Set the promise value to indicate completion
                    promise->set_value();
                } catch (const std::exception& e) {
                    log_->error("Exception in async callback: {}", e.what());
                    promise->set_exception(std::current_exception());
                }
            });
            
        // Wait for the upload to complete with a timeout
        auto status = future.wait_for(std::chrono::seconds(UPLOAD_TIMEOUT_SECONDS));
        if (status == std::future_status::timeout) {
            log_->error("Upload operation timed out after {} seconds", UPLOAD_TIMEOUT_SECONDS);
            upload_failed_ = true;
        } else {
            try {
                future.get(); // This will throw if there was an exception in the callback
            } catch (const std::exception& e) {
                log_->error("Exception during upload: {}", e.what());
                upload_failed_ = true;
            }
        }
        
    } catch (const std::exception& e) {
        log_->error("Exception in finalizeUpload: {}", e.what());
        upload_failed_ = true;
    }
}