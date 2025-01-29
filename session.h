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
#include <mutex>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <aws/core/external/cjson/cJSON.h>

#include "mp3-encoder.h"
#include "mysql-helper.h"
#include "crypto-helper.h"
#include "storage-uploader.h"

enum class StorageService {
    AWS_S3,
    S3_COMPATIBLE,
    GOOGLE_CLOUD_STORAGE,
    AZURE_CLOUD_STORAGE,
    UNKNOWN
};

class Session {
public:
    Session() ;
    ~Session();

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

    static int getActiveSessionCount();

    void setContext(const std::string& account_sid, const std::string& call_sid);

    // Add data to the session buffer
    void addData(int isBinary, const char *data, size_t len);

    // Notify the worker thread to process remaining data when connection closes
    void notifyClose() ;

private:
  static constexpr size_t BUFFER_PROCESS_SIZE = 1 * 1024 * 1024; // 1MB
  static constexpr size_t MAX_BUFFER_SIZE = 1.1 * 1024 * 1024;

  static std::once_flag initFlag_;
  static std::string uploadFolder_;

  static std::atomic<int> activeSessionCount_; // Thread-safe counter

  std::shared_ptr<spdlog::logger> log_;

  std::vector<char> buffer_; // Preallocated buffer
  std::mutex mutex_;
  std::condition_variable cv_;
  std::atomic<bool> closed_;
  std::thread worker_thread_;
  std::string tmp_;
  bool metadata_received_ = false;
  cJSON* json_metadata_;
  Metadata_t metadata_;
  std::string account_sid_;
  std::string call_sid_;

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

  // Azure cloud credentials
  std::string connection_string_;
  std::string container_name_;

  // Google cloud credentials
  std::string private_key_;
  std::string client_email_;
  std::string token_uri_;

  // Worker thread function
  void worker() {
    while (true) {
      std::vector<char> localBuffer;
      bool localClosed = false;

      localBuffer.reserve(MAX_BUFFER_SIZE);
      {
        std::unique_lock<std::mutex> lock(mutex_);

        // Wait for the condition variable to be notified
        cv_.wait(lock, [this] { return buffer_.size() >= BUFFER_PROCESS_SIZE || metadata_received_ || closed_; });

        if (buffer_.size() > 0) {
            std::swap(localBuffer, buffer_);

            // Check for misalignment in the swapped buffer
            size_t numSamples = localBuffer.size() / sizeof(short); // Total samples in localBuffer
            size_t remainder = numSamples % 2;          // do we have the same num samples for both channels?

            if (remainder != 0) {
              log_->info("Misaligned buffer: {} samples", numSamples);
              // Calculate the size of the trailing odd sample (in bytes)
              size_t leftoverSize = remainder * sizeof(short);

              // Move the trailing sample(s) back to the now-empty buffer_
              buffer_.insert(buffer_.end(), localBuffer.end() - leftoverSize, localBuffer.end());

              // Remove the trailing sample(s) from localBuffer
              localBuffer.resize(localBuffer.size() - leftoverSize);
            }

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

          log_->debug("Record Format: {}", recordCredentials_->recordFormat);

          // Decrypt the bucket credential
          std::string decryptedBucketCredential = cryptoHelper_.decrypt(recordCredentials_->bucketCredential);

          cJSON* bucketCredentialJson = cJSON_AS4CPP_Parse(decryptedBucketCredential.c_str());
          if (bucketCredentialJson) {
            cJSON* vendor = cJSON_AS4CPP_GetObjectItem(bucketCredentialJson, "vendor");
            if (vendor && cJSON_AS4CPP_IsString(vendor)) {
              if (std::string(vendor->valuestring) == "aws_s3") {
                storage_service_ = StorageService::AWS_S3;
                log_->debug("Using AWS S3 storage service.");
                parseAwsCredentials(decryptedBucketCredential);
              }
              else if(std::string(vendor->valuestring) == "s3_compatible") {
                storage_service_ = StorageService::S3_COMPATIBLE;
                log_->debug("Using S3 compatible storage service.");
                parseAwsCredentials(decryptedBucketCredential);
              }
              else if(std::string(vendor->valuestring) == "azure") {
                storage_service_ = StorageService::AZURE_CLOUD_STORAGE;
                log_->debug("Using Azure storage service.");
                parseAzureCredentials(decryptedBucketCredential);
              }
              else if(std::string(vendor->valuestring) == "google") {
                storage_service_ = StorageService::GOOGLE_CLOUD_STORAGE;
                log_->debug("Using Google storage service.");
                parseGoogleCredentials(decryptedBucketCredential);
              }
              else {
                log_->warn("Unsupported storage service: {}", vendor->valuestring);
              }
            }
            cJSON_AS4CPP_Delete(bucketCredentialJson);

            if (recordCredentials_->recordFormat == "mp3") {
              recordFileType_ = RecordFileType::MP3;
              mp3Encoder_ = std::make_unique<Mp3Encoder>(metadata_.sample_rate, 2, 128); // 128 kbps
              log_->debug("MP3 encoder created.");
            }
            else {
              recordFileType_ = RecordFileType::WAV;
            }
          }

          // Update bucket name or other information based on the record credentials
        } catch (const std::exception &e) {
          log_->warn("Failed to fetch or decrypt record credentials: {}", e.what());
          throw; // Re-throw the exception for higher-level handling if necessary
        }
      }

      // Do we have data to process ?
      if (localBuffer.size() > 0) {
        if (mp3Encoder_) {
          mp3Encoder_->encodeInPlace(localBuffer);
        }
        // Lazy initialization of the storage uploader
        if (!storageUploader_) {
          if (storageUploader_ = createStorageUploader(recordFileType_)) {
            storageUploader_->setMetadata(metadata_);
          }
        }

        if (storageUploader_) {

          if (!storageUploader_->upload(localBuffer, closed_)) {
            log_->warn("Upload failed.");
          }
        }
      }

      // Are we closing ?
      if (localClosed /*&& localBuffer.empty()*/) {
        break;
      }
    }
    log_->info("Worker thread exiting");

    if (storageUploader_) storageUploader_.reset();
  }

  void parseAwsCredentials(const std::string& credentials) ;
  void parseAzureCredentials(const std::string& credentials) ;
  void parseGoogleCredentials(const std::string& credentials) ;
  void parseMetadata(cJSON* json) ;

  // Factory method for creating a StorageUploader (you can extend this as needed)
  std::unique_ptr<StorageUploader> createStorageUploader(RecordFileType ftype);
};

#endif // _SESSION_H_