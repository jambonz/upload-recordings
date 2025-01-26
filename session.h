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

    // Add data to the session buffer
    void addData(int isBinary, const char *data, size_t len);

    // Notify the worker thread to process remaining data when connection closes
    void notifyClose() ;

private:
  static constexpr size_t BUFFER_PROCESS_SIZE = 1 * 1024 * 1024; // 1MB
  static constexpr size_t MAX_BUFFER_SIZE = 1.1 * 1024 * 1024;

  static std::once_flag initFlag_;
  static std::string uploadFolder_;

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
      bool localClosed = false;

      //std::cout << "Worker thread waiting for data..." << std::endl;
      localBuffer.reserve(MAX_BUFFER_SIZE);
      {
        std::unique_lock<std::mutex> lock(mutex_);

        // Wait for the condition variable to be notified
        cv_.wait(lock, [this] { return buffer_.size() >= BUFFER_PROCESS_SIZE || metadata_received_ || closed_; });

        //std::cout << "Worker thread notified. Buffer size: " << buffer_.size() << ", Metadata received: " << metadata_received_ << ", Closed: " << closed_ << std::endl;
        if (buffer_.size() > 0) {
            std::swap(localBuffer, buffer_);
        }
        localClosed = closed_;

        // release mutex as we go out of scope so websocket thread can continue to add data
      }
      //std::cout << "Worker thread has released mutex, processing data...\n";

      // Do we have the initial metadata to process ?
      if (metadata_received_) {
        metadata_received_ = false;
        parseMetadata(json_metadata_);
            
        try {
          recordCredentials_ = std::make_unique<RecordCredentials>(
            MySQLHelper::getInstance().fetchRecordCredentials(account_sid_)
          );

          //std::cout << "  Record Format: " << recordCredentials_->recordFormat << std::endl;

          // Decrypt the bucket credential
          std::string decryptedBucketCredential = cryptoHelper_.decrypt(recordCredentials_->bucketCredential);

          //std::cout << "Decrypted Bucket Credential: " << decryptedBucketCredential << std::endl;

          cJSON* bucketCredentialJson = cJSON_AS4CPP_Parse(decryptedBucketCredential.c_str());
          if (bucketCredentialJson) {
            cJSON* vendor = cJSON_AS4CPP_GetObjectItem(bucketCredentialJson, "vendor");
            if (vendor && cJSON_AS4CPP_IsString(vendor)) {
              if (std::string(vendor->valuestring) == "aws_s3") {
                storage_service_ = StorageService::AWS_S3;
                //std::cout << "Using AWS S3 storage service.\n";
                parseAwsCredentials(decryptedBucketCredential);
              }
              else if(std::string(vendor->valuestring) == "s3_compatible") {
                storage_service_ = StorageService::S3_COMPATIBLE;
                //std::cout << "Using S3 compatible storage service.\n";
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
              //std::cout << "MP3 encoder created.\n";
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
          //std::cout << "Processing " << std::dec << localBuffer.size() << " bytes of data...\n";

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

  void parseAwsCredentials(const std::string& credentials) ;
  void parseMetadata(cJSON* json) ;

  // Factory method for creating a StorageUploader (you can extend this as needed)
  std::unique_ptr<StorageUploader> createStorageUploader(RecordFileType ftype);
};

#endif // _SESSION_H_