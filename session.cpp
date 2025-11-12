#include <regex>

#include "session.h"
#include "s3-compatible-uploader.h"
#include "azure-uploader.h"
#include "google-uploader.h"
#include "connection-manager.h"
#include "string-utils.h"

// Static member initialization
std::once_flag Session::initFlag_;
std::string Session::uploadFolder_;
CryptoHelper Session::cryptoHelper_ = CryptoHelper();

// Static configuration variables (defaults will be overridden by main)
size_t Session::bufferProcessSize_ = 512 * 1024;     // 512KB default
size_t Session::maxBufferSize_ = 3 * 1024 * 1024;    // 3MB default
int Session::awsMaxConnections_ = 8;                  // Default

Session::Session() 
    : json_metadata_(nullptr), 
      storage_service_(StorageService::UNKNOWN),
      strand_(ThreadPool::getInstance().createStrand()) {

    // Create a unique sink for this session
    auto sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
    
    // Create a logger with its own sink
    log_ = std::make_shared<spdlog::logger>("session_logger", sink);

    buffer_.reserve(maxBufferSize_);  // Use configurable max buffer size
    initialize();
}

Session::~Session() {  
  if (json_metadata_) {
      cJSON_AS4CPP_Delete(json_metadata_);
  }
}

void Session::setContext(const std::string& account_sid, const std::string& call_sid) {
    account_sid_ = account_sid;
    call_sid_ = call_sid;

    log_->set_pattern(fmt::format("(account_sid: {}, call_sid: {}) %v", account_sid_, call_sid_));
    log_->info("Received metadata");
}

void Session::addData(int isBinary, const char *data, size_t len) {
    bool should_process = false;
    
    {
        std::unique_lock<std::mutex> lock(mutex_);

        // Check for overflow using configurable max buffer size
        if (buffer_.size() + len > maxBufferSize_) {
            log_->error("Buffer overflow: dropping data, buffer size is {}", buffer_.size());
            return;
        }

        if (isBinary) {
            buffer_.insert(buffer_.end(), data, data + len);

            // Process the buffer if it reaches the configurable threshold
            if (buffer_.size() >= bufferProcessSize_) {
                should_process = true;
            }
        } 
        else if (!json_metadata_) {
            tmp_.append(data, len);
            cJSON *json = cJSON_AS4CPP_Parse(tmp_.c_str());
            if (json != nullptr) {
                json_metadata_ = json;
                metadata_received_ = true;
                postProcessMetadataTask();
            }
        }
        else {
            log_->info("Unexpected text frame after metadata: {}", std::string(data, len));
        }
    }
    
    if (should_process) {
        postProcessBufferTask(false);
    }
}

void Session::notifyClose() {
    log_->info("connection closed");
    postProcessBufferTask(true);
}

void Session::postProcessMetadataTask() {
    auto self = shared_from_this();

    std::string threadId = getThreadIdString();
    log_->info("read metadata in threadId: {}", threadId);
    
    // Post to strand to ensure sequential processing
    boost::asio::post(strand_, [self]() {
        self->processMetadata();
    });
}

void Session::postProcessBufferTask(bool isFinal) {
    auto self = shared_from_this();
    
    // Post to strand to ensure sequential processing
    boost::asio::post(strand_, [self, isFinal]() {
        self->processBuffer(isFinal);
    });
}

void Session::processMetadata() {
    std::string threadId = getThreadIdString();
    log_->info("processing metadata in threadId: {}", threadId);  
    parseMetadata(json_metadata_);
        
    try {
        recordCredentials_ = std::make_unique<RecordCredentials>(
            MySQLHelper::getInstance().fetchRecordCredentials(account_sid_)
        );

        log_->info("Record Format: {}", recordCredentials_->recordFormat);

        // Decrypt the bucket credential
        std::string decryptedBucketCredential = cryptoHelper_.decrypt(recordCredentials_->bucketCredential);

        cJSON* bucketCredentialJson = cJSON_AS4CPP_Parse(decryptedBucketCredential.c_str());
        if (bucketCredentialJson) {
            cJSON* vendor = cJSON_AS4CPP_GetObjectItem(bucketCredentialJson, "vendor");
            if (vendor && cJSON_AS4CPP_IsString(vendor)) {
                if (std::string(vendor->valuestring) == "aws_s3") {
                    storage_service_ = StorageService::AWS_S3;
                    log_->info("Using AWS S3 storage service.");
                    parseAwsCredentials(decryptedBucketCredential);
                }
                else if(std::string(vendor->valuestring) == "s3_compatible") {
                    storage_service_ = StorageService::S3_COMPATIBLE;
                    log_->info("Using S3 compatible storage service.");
                    parseAwsCredentials(decryptedBucketCredential);
                }
                else if(std::string(vendor->valuestring) == "azure") {
                    storage_service_ = StorageService::AZURE_CLOUD_STORAGE;
                    log_->info("Using Azure storage service.");
                    parseAzureCredentials(decryptedBucketCredential);
                }
                else if(std::string(vendor->valuestring) == "google") {
                    storage_service_ = StorageService::GOOGLE_CLOUD_STORAGE;
                    log_->info("Using Google storage service.");
                    parseGoogleCredentials(decryptedBucketCredential);
                }
                else {
                    log_->warn("Unsupported storage service: {}", vendor->valuestring);
                }
            }
            cJSON_AS4CPP_Delete(bucketCredentialJson);

            if (recordCredentials_->recordFormat == "mp3") {
                recordFileType_ = RecordFileType::MP3;
                // MP3 encoder will be created in the storage uploader at the end
                log_->info("Recording format set to MP3 (encoding will happen at end).");
            }
            else {
                recordFileType_ = RecordFileType::WAV;
            }
        }

        // initialization of the storage uploader
        if (!storageUploader_) {
          if ((storageUploader_ = createStorageUploader(recordFileType_))) {
              storageUploader_->setMetadata(metadata_);
          }
        }
    } catch (const std::exception &e) {
        log_->error("Failed to fetch or decrypt record credentials: {}", e.what());
    }
}

void Session::processBuffer(bool isFinal) {
  std::vector<char> localBuffer;
  bool process_buffer = false;

  {
      std::unique_lock<std::mutex> lock(mutex_);

      if (!buffer_.empty()) {
          std::swap(localBuffer, buffer_);

          // Handle misalignment in the swapped buffer
          size_t numSamples = localBuffer.size() / sizeof(short); // Total samples in localBuffer
          size_t remainder = numSamples % 2;    // Do we have the same num samples for both channels?

          if (remainder != 0) {
              log_->info("Misaligned buffer: {} samples", numSamples);

              // Only move leftover samples back to buffer_ if this is NOT the final chunk
              // If it's the final chunk, we need to upload all remaining data
              if (!isFinal) {
                  // Calculate the size of the trailing odd sample (in bytes)
                  size_t leftoverSize = remainder * sizeof(short);

                  // Move the trailing sample(s) back to the now-empty buffer_
                  buffer_.insert(buffer_.end(), localBuffer.end() - leftoverSize, localBuffer.end());

                  // Remove the trailing sample(s) from localBuffer
                  localBuffer.resize(localBuffer.size() - leftoverSize);
              } else {
                  log_->info("Final chunk: including all {} samples in upload", numSamples);
              }
          }

          process_buffer = true;
      }
  }
  
  // Process the buffer if we have data
  if (process_buffer) {
      log_->debug("Processing buffer of size: {}", localBuffer.size());
      
      // No longer encode MP3 here - just write raw PCM data
      
      if (storageUploader_) {
          if (!storageUploader_->upload(localBuffer, isFinal)) {
              log_->error("Upload failed.");
              //TODO: handle error somehow? End session??
          }
      }
  }
  else if (isFinal) {
    if (storageUploader_) {
      std::string threadId = getThreadIdString();
      log_->info("uploading recording in threadId: {}", threadId);  
  
      storageUploader_->upload(localBuffer, isFinal);
    }
    else {
      // Here we have the case where we did not get metadata so we have no uploader
      // We need to orchestrate the destruction of this Session at this point
      log_->warn("Session::processBuffer connection closed but no StorageUploader.");
      auto self = shared_from_this();
      ConnectionManager::getInstance().destroySession(self.get());
    }
  }
}

void Session::parseAwsCredentials(const std::string& credentials) {
  // Parse the credentials JSON
  cJSON* json = cJSON_AS4CPP_Parse(credentials.c_str());
  if (!json) {
    std::cerr << "Failed to parse AWS credentials JSON.\n";
    return;
  }

  cJSON* accessKey = cJSON_AS4CPP_GetObjectItem(json, "access_key_id");
  if (accessKey && cJSON_AS4CPP_IsString(accessKey)) {
    access_key_ = accessKey->valuestring;
  }

  cJSON* secretKey = cJSON_AS4CPP_GetObjectItem(json, "secret_access_key");
  if (secretKey && cJSON_AS4CPP_IsString(secretKey)) {
    secret_key_ = secretKey->valuestring;
  }

  cJSON* bucketName = cJSON_AS4CPP_GetObjectItem(json, "name");
  if (bucketName && cJSON_AS4CPP_IsString(bucketName)) {
    bucket_name_ = bucketName->valuestring;
  }

  cJSON* endpoint = cJSON_AS4CPP_GetObjectItem(json, "endpoint");
  if (endpoint && cJSON_AS4CPP_IsString(endpoint)) {
    custom_endpoint_ = endpoint->valuestring;
  }

  // First try to get region from the "region" property
  cJSON* region = cJSON_AS4CPP_GetObjectItem(json, "region");
  if (region && cJSON_AS4CPP_IsString(region)) {
    region_ = region->valuestring;
  } 
  // If no region was found but we have an endpoint, try to extract region from endpoint
  else if (!custom_endpoint_.empty()) {
    extractRegionFromEndpoint(custom_endpoint_, region_);
  }

  cJSON_AS4CPP_Delete(json);
}

void Session::parseAzureCredentials(const std::string& credentials) {
  cJSON* json = cJSON_AS4CPP_Parse(credentials.c_str());
  if (!json) {
    std::cerr << "Failed to parse Azure credentials JSON.\n";
    return;
  }

  cJSON* containerName = cJSON_AS4CPP_GetObjectItem(json, "name");
  if (containerName && cJSON_AS4CPP_IsString(containerName)) {
    container_name_ = containerName->valuestring;
  }

  cJSON* connectionString = cJSON_AS4CPP_GetObjectItem(json, "connection_string");
  if (connectionString && cJSON_AS4CPP_IsString(connectionString)) {
    connection_string_ = connectionString->valuestring;
  }

  cJSON_AS4CPP_Delete(json);
}

void Session::parseGoogleCredentials(const std::string& credentials) {
    cJSON* json = cJSON_AS4CPP_Parse(credentials.c_str());
    if (!json) {
        std::cerr << "Failed to parse Google credentials JSON.\n";
        return;
    }

    // Extract the bucket name
    cJSON* bucketName = cJSON_AS4CPP_GetObjectItem(json, "name");
    if (bucketName && cJSON_AS4CPP_IsString(bucketName)) {
        bucket_name_ = bucketName->valuestring;
    }

    // Extract the service_key field
    cJSON* serviceKey = cJSON_AS4CPP_GetObjectItem(json, "service_key");
    if (serviceKey && cJSON_AS4CPP_IsString(serviceKey)) {
        cJSON* serviceKeyJson = cJSON_AS4CPP_Parse(serviceKey->valuestring);
        if (serviceKeyJson) {
            // Extract the private_key
            cJSON* privateKey = cJSON_AS4CPP_GetObjectItem(serviceKeyJson, "private_key");
            if (privateKey && cJSON_AS4CPP_IsString(privateKey)) {
                private_key_ = privateKey->valuestring;
            }

            // Extract the client_email
            cJSON* clientEmail = cJSON_AS4CPP_GetObjectItem(serviceKeyJson, "client_email");
            if (clientEmail && cJSON_AS4CPP_IsString(clientEmail)) {
                client_email_ = clientEmail->valuestring;
            }

            // Extract the token_uri
            cJSON* tokenUri = cJSON_AS4CPP_GetObjectItem(serviceKeyJson, "token_uri");
            if (tokenUri && cJSON_AS4CPP_IsString(tokenUri)) {
                token_uri_ = tokenUri->valuestring;
            }

            cJSON_AS4CPP_Delete(serviceKeyJson); // Clean up the parsed service key JSON
        } else {
            std::cerr << "Failed to parse service_key JSON.\n";
        }
    }

    log_->info("parseGoogleCredentials: bucket_name = {}", bucket_name_);

    cJSON_AS4CPP_Delete(json); // Clean up the main JSON object
}

void Session::parseMetadata(cJSON* json) {
  if (!json) {
    std::cerr << "Invalid JSON object for metadata parsing.\n";
    return;
  }

  cJSON* sampleRate = cJSON_AS4CPP_GetObjectItem(json, "sampleRate");
  if (sampleRate && cJSON_AS4CPP_IsNumber(sampleRate)) {
    metadata_.sample_rate = sampleRate->valueint;
  }

  cJSON* accountSid = cJSON_AS4CPP_GetObjectItem(json, "accountSid");
  if (accountSid && cJSON_AS4CPP_IsString(accountSid)) {
    account_sid_ = accountSid->valuestring;
  }

  cJSON* callSid = cJSON_AS4CPP_GetObjectItem(json, "callSid");
  if (callSid && cJSON_AS4CPP_IsString(callSid)) {
    metadata_.call_sid = call_sid_ = callSid->valuestring;
  }

  cJSON* direction = cJSON_AS4CPP_GetObjectItem(json, "direction");
  if (direction && cJSON_AS4CPP_IsString(direction)) {
    metadata_.direction = direction->valuestring;
  }

  cJSON* from = cJSON_AS4CPP_GetObjectItem(json, "from");
  if (from && cJSON_AS4CPP_IsString(from)) {
    metadata_.from = from->valuestring;
  }

  cJSON* to = cJSON_AS4CPP_GetObjectItem(json, "to");
  if (to && cJSON_AS4CPP_IsString(to)) {
    metadata_.to = to->valuestring;
  }

  cJSON* applicationSid = cJSON_AS4CPP_GetObjectItem(json, "applicationSid");
  if (applicationSid && cJSON_AS4CPP_IsString(applicationSid)) {
    metadata_.application_sid = applicationSid->valuestring;
  }

  cJSON* originatingSipIp = cJSON_AS4CPP_GetObjectItem(json, "originatingSipIp");
  if (originatingSipIp && cJSON_AS4CPP_IsString(originatingSipIp)) {
    metadata_.originating_sip_id = originatingSipIp->valuestring;
  }

  cJSON* originatingSipTrunkName = cJSON_AS4CPP_GetObjectItem(json, "fsSipAddress");
  if (originatingSipTrunkName && cJSON_AS4CPP_IsString(originatingSipTrunkName)) {
    metadata_.originating_sip_trunk_name = originatingSipTrunkName->valuestring;
  }

  setContext(account_sid_, call_sid_);
}

std::unique_ptr<StorageUploader> Session::createStorageUploader(RecordFileType ftype) {
  try {
    switch (storage_service_) {
      case StorageService::AWS_S3:
        return std::make_unique<S3CompatibleUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          Aws::Auth::AWSCredentials(access_key_, secret_key_),
          region_,
          bucket_name_
        );

      case StorageService::S3_COMPATIBLE:
        return std::make_unique<S3CompatibleUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          Aws::Auth::AWSCredentials(access_key_, secret_key_),
          region_,
          bucket_name_,
          custom_endpoint_
        );
      case StorageService::AZURE_CLOUD_STORAGE:
        return std::make_unique<AzureUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          connection_string_,
          container_name_
        );
      case StorageService::GOOGLE_CLOUD_STORAGE:
        return std::make_unique<GoogleUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          bucket_name_,
          client_email_,
          private_key_,
          token_uri_
        );
      default:
        std::cerr << "Unknown storage service.\n";
        return nullptr;
    }
  } catch (const std::exception &e) {
    log_->error("Failed to create storage uploader: {}", e.what());
    return nullptr;
  }
}

void Session::extractRegionFromEndpoint(const std::string& endpoint, std::string& regionVar) {
  // This regex looks for:
  // 1. Optional protocol (http:// or https://) or start of string
  // 2. "s3." prefix
  // 3. A region segment containing a hyphen
  // 4. Followed by a period and at least two more domain segments
  std::regex region_pattern(R"((^|://|^)s3\.([^\.]+\-[^\.]+)\.[^\.]+\.[^\.]+)");
  std::smatch matches;
  
  if (std::regex_search(endpoint, matches, region_pattern) && matches.size() > 2) {
    // Only update the region variable if we successfully extracted a region
    regionVar = matches[2].str();
    log_->info("Extracted region from endpoint: {}", regionVar);
  }
  // If no match is found, regionVar remains unchanged
}