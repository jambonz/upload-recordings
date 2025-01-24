#ifndef STORAGE_UPLOADER_H
#define STORAGE_UPLOADER_H

#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <ctime>

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
    virtual ~StorageUploader() = default;

    // Upload method to be implemented by derived classes
    virtual bool upload(std::vector<char>& data, bool isFinalChunk = false) = 0;

    // Store metadata
    void setMetadata(const struct Metadata_t& metadata) {
        metadata_ = metadata;
    }

protected:

  std::string createObjectPath(const std::string& callSid, const std::string& recordFormat) {
    // Get the current date and time
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);

    // Create a string stream to format the path
    std::ostringstream pathStream;

    // Append year, month, and day, formatted as YYYY/MM/DD
    pathStream << tm.tm_year + 1900 << "/"
              << std::setfill('0') << std::setw(2) << tm.tm_mon + 1 << "/"
              << std::setfill('0') << std::setw(2) << tm.tm_mday << "/";

    // Append the callSid and recordFormat to the path
    pathStream << callSid << "." << recordFormat;

    return pathStream.str();
  }

  struct Metadata_t metadata_;
  bool upload_in_progress_;
  bool upload_failed_;
};

#endif // STORAGE_UPLOADER_H
