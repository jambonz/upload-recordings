// session.h (Modified version)
#ifndef _SESSION_H_
#define _SESSION_H_

#include <mutex>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <aws/core/external/cjson/cJSON.h>

#include "thread-pool.h"
#include "mp3-encoder.h"
#include "mysql-helper.h"
#include "crypto-helper.h"
#include "storage-uploader.h"
#include "config.h"

enum class StorageService {
    AWS_S3,
    S3_COMPATIBLE,
    GOOGLE_CLOUD_STORAGE,
    AZURE_CLOUD_STORAGE,
    UNKNOWN
};

// Modified Session class that works with thread pool
class Session : public std::enable_shared_from_this<Session> {
public:
    Session();
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

    void setContext(const std::string& account_sid, const std::string& call_sid);

    // Add data to the session buffer
    void addData(int isBinary, const char *data, size_t len);

    void notifyClose();

    template <typename... Args>
    void log(const char* fmt, Args... args) {
        log_->info(fmt, args...);
    }

private:
    static std::once_flag initFlag_;
    static std::string uploadFolder_;
    static CryptoHelper cryptoHelper_;

    std::shared_ptr<spdlog::logger> log_;
    boost::asio::io_context::strand strand_; // Strand for serialized task execution

    std::vector<char> buffer_; // Buffer for audio data
    std::mutex mutex_;         // Protect access to the buffer
    std::atomic<bool> closed_; // Flag to indicate session is closed
    std::string tmp_;          // Temporary buffer for text data
    bool metadata_received_ = false;
    cJSON* json_metadata_;
    Metadata_t metadata_;
    std::string account_sid_;
    std::string call_sid_;

    RecordFileType recordFileType_;
    StorageService storage_service_;
    std::unique_ptr<StorageUploader> storageUploader_;
    std::unique_ptr<RecordCredentials> recordCredentials_;
    std::unique_ptr<Mp3Encoder> mp3Encoder_;

    // Credentials for different storage services
    std::string bucket_name_;
    std::string access_key_;
    std::string secret_key_;
    std::string region_;
    std::string custom_endpoint_;
    std::string connection_string_;
    std::string container_name_;
    std::string private_key_;
    std::string client_email_;
    std::string token_uri_;

    // Helper methods for task-based processing
    void postProcessMetadataTask();
    void postProcessBufferTask(bool isFinal);
    
    // Processing methods that run in the thread pool
    void processMetadata();
    void processBuffer(bool isFinal);

    // Credential parsing methods (unchanged)
    void parseAwsCredentials(const std::string& credentials);
    void parseAzureCredentials(const std::string& credentials);
    void parseGoogleCredentials(const std::string& credentials);
    void parseMetadata(cJSON* json);
    void extractRegionFromEndpoint(const std::string& endpoint, std::string& regionVar);
    
    // Factory method for creating a StorageUploader
    std::unique_ptr<StorageUploader> createStorageUploader(RecordFileType ftype);
};

#endif // _SESSION_H_