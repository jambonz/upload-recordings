#include "session.h"
#include "s3-compatible-uploader.h"
#include "azure-uploader.h"
#include "google-uploader.h"

// Static member initialization
std::once_flag Session::initFlag_;
std::string Session::uploadFolder_;
CryptoHelper Session::cryptoHelper_ = CryptoHelper();
std::atomic<int> Session::activeSessionCount_{0};

Session::Session() : json_metadata_(nullptr), closed_(false), storage_service_(StorageService::UNKNOWN) {
  ++activeSessionCount_;

  // Create a unique sink for this session
  auto sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
  
  // Create a logger with its own sink
  log_ = std::make_shared<spdlog::logger>("session_logger", sink);

  buffer_.reserve(MAX_BUFFER_SIZE);
  initialize();
  worker_thread_ = std::thread(&Session::worker, this);
}

Session::~Session() {
  --activeSessionCount_; 
  {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true; // Mark the session as closed
  }
  if (json_metadata_) {
    cJSON_AS4CPP_Delete(json_metadata_);
  }
  cv_.notify_one(); // Wake up the worker thread
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
  log_->info("destroyed session, there are now {} active sessions", Session::getActiveSessionCount());
}

int Session::getActiveSessionCount() {
    return activeSessionCount_.load(); // Get the current value atomically
}

void Session::setContext(const std::string& account_sid, const std::string& call_sid) {
  account_sid_ = account_sid;
  call_sid_ = call_sid;

  log_->set_pattern(fmt::format("(account_sid: {}, call_sid: {}) %v", account_sid_, call_sid_));

  log_->info("created session, there are now {} active sessions", Session::getActiveSessionCount());
}

void Session::addData(int isBinary, const char *data, size_t len) {
  {
    std::unique_lock<std::mutex> lock(mutex_);

    // Check for overflow
    if (buffer_.size() + len > MAX_BUFFER_SIZE) {
      std::cerr << "Buffer overflow: dropping data, buffer_ size is " << std::dec << buffer_.size() << std::endl;
      return;
    }

    if (isBinary) {
      buffer_.insert(buffer_.end(), data, data + len);

      // Notify the worker thread if the buffer size reaches the threshold
      if (buffer_.size() >= BUFFER_PROCESS_SIZE) {
        cv_.notify_one();
      }
    } 
    else if (!json_metadata_) {
      tmp_.append(data, len);
      cJSON *json = cJSON_AS4CPP_Parse(tmp_.c_str());
      if (json != nullptr) {
        json_metadata_ = json;
        metadata_received_ = true;

        cv_.notify_one(); // Notify the worker thread to process metadata
      }
    }
    else {
      log_->debug("Unexpected text frame after metadata: {}", std::string(data, len));
    }
  }
}

void Session::notifyClose() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
  }
  cv_.notify_one();
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

  cJSON* region = cJSON_AS4CPP_GetObjectItem(json, "region");
  if (region && cJSON_AS4CPP_IsString(region)) {
    region_ = region->valuestring;
  }

  cJSON* bucketName = cJSON_AS4CPP_GetObjectItem(json, "name");
  if (bucketName && cJSON_AS4CPP_IsString(bucketName)) {
    bucket_name_ = bucketName->valuestring;
  }

  cJSON* endpoint = cJSON_AS4CPP_GetObjectItem(json, "endpoint");
  if (endpoint && cJSON_AS4CPP_IsString(endpoint)) {
    custom_endpoint_ = endpoint->valuestring;
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

    log_->debug("parseGoogleCredentials: bucket_name = {}", bucket_name_);

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
          log_,
          uploadFolder_,
          ftype,
          Aws::Auth::AWSCredentials(access_key_, secret_key_),
          region_,
          bucket_name_
        );

      case StorageService::S3_COMPATIBLE:
        return std::make_unique<S3CompatibleUploader>(
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
          log_,
          uploadFolder_,
          ftype,
          connection_string_,
          container_name_
        );
      case StorageService::GOOGLE_CLOUD_STORAGE:
        return std::make_unique<GoogleUploader>(
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
