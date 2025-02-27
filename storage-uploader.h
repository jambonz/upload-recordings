#ifndef STORAGE_UPLOADER_H
#define STORAGE_UPLOADER_H

#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <atomic>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <memory>

// Forward declaration of Session
class Session;

enum class RecordFileType {
    WAV,
    MP3,
    UNKNOWN
};

struct Metadata_t {
  std::string account_sid;
  std::string call_sid;
  std::string direction;
  std::string from;
  std::string to;
  std::string application_sid;
  std::string originating_sip_id;
  std::string originating_sip_trunk_name;
  uint32_t sample_rate;
};

class StorageUploader {
public:
    StorageUploader(const std::shared_ptr<Session>& session) : sessionRef_(session) {
    }
    
    virtual ~StorageUploader() {
    }

    // Upload method to be implemented by derived classes
    virtual bool upload(std::vector<char>& data, bool isFinalChunk = false) = 0;

    // Store metadata
    void setMetadata(const struct Metadata_t& metadata) {
        metadata_ = metadata;
    }

    void setLogger(std::shared_ptr<spdlog::logger> log) {
        log_ = log;
    }

protected:
    // Create a unique temporary file
    void createTempFile(const std::string& uploadFolder);

    // Cleanup the temporary file
    void cleanupTempFile();

    // Create the object path for upload
    std::string createObjectPath(const std::string& callSid, const std::string& recordFormat);

    std::shared_ptr<spdlog::logger> log_;

    struct Metadata_t metadata_;
    bool upload_in_progress_ = false;
    bool upload_failed_ = false;

    std::string tempFilePath_;
    std::ofstream tempFile_;

    // weak reference to the session so we can trigger its destruction after upload completion
    std::weak_ptr<Session> sessionRef_;

    // Static atomic counter for generating unique file names
    static std::atomic<int> uniqueCounter;

};

#endif // STORAGE_UPLOADER_H