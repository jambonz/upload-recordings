#ifndef _SESSION_H_
#define _SESSION_H_

#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <iostream>
#include <cstring>
#include <iostream>
#include <string>
#include <memory>

#include <aws/core/external/cjson/cJSON.h>

#include "s3-uploader.h"
#include "s3-compatible-uploader.h"
#include "mp3-encoder.h"
#include "mysql-helper.h"
#include "crypto-helper.h"

enum class StorageService {
    AWS_S3,
    S3_COMPATIBLE,
    GOOGLE_CLOUD_STORAGE,
    AZURE_CLOUD_STORAGE,
    UNKNOWN
};

class Session {
public:
    Session() : buffer_size_(0), json_metadata_(nullptr), closed_(false), storage_service_(StorageService::UNKNOWN) {
        // Preallocate the full buffer size upfront
        buffer_.reserve(MAX_BUFFER_SIZE);

        initialize();

        // Start the worker thread
        worker_thread_ = std::thread(&Session::worker, this);
    }

    ~Session() {
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

    static void initialize() {
        std::call_once(initFlag_, []() {
          const char* tempFolderEnv = std::getenv("JAMBONZ_UPLOADER_TMP_FOLDER");
          uploadFolder_ = tempFolderEnv ? tempFolderEnv : "/tmp/uploads";

          // Ensure the folder exists
          std::system(("mkdir -p " + uploadFolder_).c_str());
        });
    }

    static std::string getUploadFolder() {
      return uploadFolder_;
    }

    // Add data to the session buffer
    void addData(int isBinary, const char *data, size_t len);

    // Notify the worker thread to process remaining data when connection closes
    void notifyClose() ;

private:
  static constexpr size_t BUFFER_PROCESS_SIZE = 5 * 1024 * 1024; // 5MB
  static constexpr size_t MAX_BUFFER_SIZE = 6 * 1024 * 1024; // 6MB

  static std::once_flag initFlag_;
  static std::string uploadFolder_;

  std::vector<char> buffer_; // Preallocated buffer
  size_t buffer_size_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::atomic<bool> closed_;
  std::thread worker_thread_;
  std::string tmp_;
  bool metadata_received_ = false;
  cJSON* json_metadata_;
  Metadata_t metadata_;
  std::string account_sid_;

  RecordFileType recordFileType_;
  StorageService storage_service_;
  std::unique_ptr<StorageUploader> storageUploader_;

  std::unique_ptr<RecordCredentials> recordCredentials_;

  // mp3 encoding
  std::unique_ptr<Mp3Encoder> mp3Encoder_;

  // decryption of credentials
  static CryptoHelper cryptoHelper_;


  // AWS S3 or compatible credentials
  std::string bucket_name_;
  std::string access_key_;
  std::string secret_key_;
  std::string region_;
  std::string custom_endpoint_;

  // Worker thread function
  void worker() {
    while (true) {
      std::vector<char> localBuffer;
      size_t localBufferSize = 0;
      bool localClosed = false;

      {
        std::unique_lock<std::mutex> lock(mutex_);

        // Wait for the condition variable to be notified
        cv_.wait(lock, [this] { return buffer_size_ >= MAX_BUFFER_SIZE || metadata_received_ || closed_; });

        std::cout << "Worker thread notified...\n";
        if (buffer_size_ > 0) {
            localBuffer.assign(buffer_.begin(), buffer_.begin() + buffer_size_);
            localBufferSize = buffer_size_;
            buffer_.clear();
            buffer_size_ = 0;
        }
        localClosed = closed_;

        // release mutex as we go out of scope so websocket thread can continue to add data
      }

      // Do we have the initial metadata to process ?
      if (metadata_received_) {
        metadata_received_ = false;
        parseMetadata(json_metadata_);
            
        try {
          recordCredentials_ = std::make_unique<RecordCredentials>(
            MySQLHelper::getInstance().fetchRecordCredentials(account_sid_)
          );

          std::cout << "Fetched record credentials:\n";
          std::cout << "  Record Format: " << recordCredentials_->recordFormat << std::endl;
          //std::cout << "  Bucket Credential: " << recordCredentials_->bucketCredential << std::endl;

          // Decrypt the bucket credential
          std::string decryptedBucketCredential = cryptoHelper_.decrypt(recordCredentials_->bucketCredential);

          std::cout << "Decrypted Bucket Credential: " << decryptedBucketCredential << std::endl;

          cJSON* bucketCredentialJson = cJSON_AS4CPP_Parse(decryptedBucketCredential.c_str());
          if (bucketCredentialJson) {
            cJSON* vendor = cJSON_AS4CPP_GetObjectItem(bucketCredentialJson, "vendor");
            if (vendor && cJSON_AS4CPP_IsString(vendor)) {
              if (std::string(vendor->valuestring) == "aws_s3") {
                storage_service_ = StorageService::AWS_S3;
                std::cout << "Using AWS S3 storage service.\n";
                parseAwsCredentials(decryptedBucketCredential);
              }
              else if(std::string(vendor->valuestring) == "s3_compatible") {
                storage_service_ = StorageService::S3_COMPATIBLE;
                std::cout << "Using S3 compatible storage service.\n";
                parseAwsCredentials(decryptedBucketCredential);
              }
              else {
                std::cerr << "Unsupported storage service: " << vendor->valuestring << std::endl;
              }
            }
            cJSON_AS4CPP_Delete(bucketCredentialJson);

            if (recordCredentials_->recordFormat == "mp3") {
              recordFileType_ = RecordFileType::MP3;
              mp3Encoder_ = std::make_unique<Mp3Encoder>(metadata_.sample_rate, 2, 128); // 128 kbps
              std::cout << "MP3 encoder created.\n";
            }
            else {
              recordFileType_ = RecordFileType::WAV;
            }
          }

          // Update bucket name or other information based on the record credentials
        } catch (const std::exception &e) {
          std::cerr << "Failed to fetch or decrypt record credentials: " << e.what() << std::endl;
          throw; // Re-throw the exception for higher-level handling if necessary
        }
      }

      // Do we have data to process ?
      if (!localBuffer.empty()) {

        // mp3 encoding if required
        if (mp3Encoder_) {
          std::cout << "Encoding " << localBufferSize << " bytes of data...\n";
          mp3Encoder_->encodeInPlace(localBuffer);
        }
        // Lazy initialization of the storage uploader
        if (!storageUploader_) {
          if (storageUploader_ = createStorageUploader(recordFileType_)) {
            std::cout << "Storage uploader created.\n";
            storageUploader_->setMetadata(metadata_);
          }
        }

        if (storageUploader_) {
          std::cout << "Processing " << std::dec << localBufferSize << " bytes of data...\n";
          if (!storageUploader_->upload(localBuffer, closed_)) {
              std::cerr << "Upload failed.\n";
          }
        }
      }

      // Are we closing ?
      if (localClosed && localBuffer.empty()) {
        break;
      }
    }

    if (storageUploader_) storageUploader_.reset();
    std::cout << "Worker thread exiting...\n";
  }

  void parseAwsCredentials(const std::string& credentials) {
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

  void parseMetadata(cJSON* json) {
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

    std::cout << "Parsed metadata:\n"
              << "  sample_rate: " << metadata_.sample_rate << std::endl
              << "  call_sid: " << metadata_.call_sid << std::endl
              << "  direction: " << metadata_.direction << std::endl
              << "  from: " << metadata_.from << std::endl
              << "  to: " << metadata_.to << std::endl
              << "  application_sid: " << metadata_.application_sid << std::endl
              << "  originating_sip_id: " << metadata_.originating_sip_id << std::endl
              << "  originating_sip_trunk_name: " << metadata_.originating_sip_trunk_name << std::endl;
  }

  // Factory method for creating a StorageUploader (you can extend this as needed)
  std::unique_ptr<StorageUploader> createStorageUploader(RecordFileType ftype) {
    switch (storage_service_) {
        case StorageService::AWS_S3:
          return std::make_unique<S3Uploader>(
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
};

#endif // _SESSION_H_