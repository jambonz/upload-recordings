#ifndef GOOGLE_UPLOADER_H
#define GOOGLE_UPLOADER_H

#include "storage-uploader.h"
#include <string>
#include <vector>
#include <curl/curl.h>

class GoogleUploader : public StorageUploader {
public:
    GoogleUploader(std::shared_ptr<spdlog::logger> log, std::string& uploadFolder, 
      RecordFileType ftype, const std::string& bucketName, const std::string& clientEmail, 
      const std::string& privateKey, const std::string& tokenUri);
    ~GoogleUploader();

    bool upload(std::vector<char>& data, bool isFinalChunk = false) override;

    static size_t writeHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata);

private:
    std::string generateOAuthToken(); // Generate an OAuth 2.0 token
    std::string initiateResumableUpload(); // Start a resumable upload session
    bool uploadFileInChunks(const std::string &filePath, const std::string &sessionUrl);
    bool uploadChunkWithRange(const std::string &sessionUrl, const char* data, size_t dataSize, size_t offset, size_t totalSize);
    void finalizeUpload(); 

    std::string clientEmail_;
    std::string privateKey_;
    std::string tokenUri_;

    std::string bucketName_;
    std::string objectKey_;
    RecordFileType recordFileType_;
    std::string uploadSessionUrl_; // URL for resumable upload session
    std::string accessToken_; // OAuth 2.0 access token
    CURL* curl_;
    struct curl_slist* headers_;

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);

};

#endif // GOOGLE_UPLOADER_H