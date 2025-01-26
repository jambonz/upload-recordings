#include "session.h"

// Static member initialization
std::once_flag Session::initFlag_;
std::string Session::uploadFolder_;
CryptoHelper Session::cryptoHelper_ = CryptoHelper();

Session::Session() : json_metadata_(nullptr), closed_(false), storage_service_(StorageService::UNKNOWN) {
  buffer_.reserve(MAX_BUFFER_SIZE);
  initialize();
  worker_thread_ = std::thread(&Session::worker, this);
}

Session::~Session() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true; // Mark the session as closed
  }
  if (json_metadata_) {
    cJSON_AS4CPP_Delete(json_metadata_);
  }
  cv_.notify_all(); // Wake up the worker thread
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
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
        cv_.notify_all();
      }
    } 
    else if (!json_metadata_) {
      tmp_.append(data, len);
      cJSON *json = cJSON_AS4CPP_Parse(tmp_.c_str());
      if (json != nullptr) {
        json_metadata_ = json;
        metadata_received_ = true;
        //std::cout << "Valid JSON metadata received: " << tmp_ << std::endl;

        cv_.notify_all(); // Notify the worker thread to process metadata
      }
    }
    else {
      std::cerr << "Unexpected text frame after metadata: " << std::string(data, len) << std::endl;
    }
  }
}

void Session::notifyClose() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
  }
  cv_.notify_all();
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
  metadata_.call_sid = callSid->valuestring;
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

/*
std::cout << "Parsed metadata:\n"
          << "  sample_rate: " << metadata_.sample_rate << std::endl
          << "  call_sid: " << metadata_.call_sid << std::endl
          << "  direction: " << metadata_.direction << std::endl
          << "  from: " << metadata_.from << std::endl
          << "  to: " << metadata_.to << std::endl
          << "  application_sid: " << metadata_.application_sid << std::endl
          << "  originating_sip_id: " << metadata_.originating_sip_id << std::endl
          << "  originating_sip_trunk_name: " << metadata_.originating_sip_trunk_name << std::endl;
*/
}

std::unique_ptr<StorageUploader> Session::createStorageUploader(RecordFileType ftype) {
  switch (storage_service_) {
      case StorageService::AWS_S3:
        return std::make_unique<S3CompatibleUploader>(
            uploadFolder_,
            ftype,
            Aws::Auth::AWSCredentials(access_key_, secret_key_),
            region_,
            bucket_name_
        );

      case StorageService::S3_COMPATIBLE:
        return std::make_unique<S3CompatibleUploader>(
            uploadFolder_,
            ftype,
            Aws::Auth::AWSCredentials(access_key_, secret_key_),
            region_,
            bucket_name_,
            custom_endpoint_
        );
      case StorageService::GOOGLE_CLOUD_STORAGE:
          std::cerr << "Google Cloud Storage uploader not implemented yet.\n";
          return nullptr;
      case StorageService::AZURE_CLOUD_STORAGE:
          std::cerr << "Azure Cloud Storage uploader not implemented yet.\n";
          return nullptr;
      default:
          std::cerr << "Unknown storage service.\n";
          return nullptr;
  }
}
