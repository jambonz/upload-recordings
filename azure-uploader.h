#ifndef AZURE_UPLOADER_H
#define AZURE_UPLOADER_H

#include "storage-uploader.h"
#include <string>
#include <vector>
#include <curl/curl.h>

class AzureUploader : public StorageUploader {
public:
    AzureUploader(const std::shared_ptr<Session>& session, std::shared_ptr<spdlog::logger> log,  std::string& uploadFolder, RecordFileType ftype,
                  const std::string& connectionString, const std::string& containerName);
    ~AzureUploader();

    bool upload(std::vector<char>& data, bool isFinalChunk = false) override;


private:
  std::string generateAuthorizationHeader(const std::string& httpMethod, const std::string& url, const std::string& contentLength);

    std::string accountName_;
    std::string accountKey_;
    std::string endpointSuffix_;
    std::string containerName_;
    std::string uploadUrlBase_;
    std::string uploadUrl_;
    std::string objectKey_;
    RecordFileType recordFileType_;
    std::vector<std::string> blockIds_;
    std::string xMsDate_;
    size_t blockSize_;

    CURL* curl_;
    struct curl_slist* headers_;

    bool uploadFileInBlocks(const std::string &filePath);
    bool uploadBlock(const char* data, size_t size, const std::string &blockId);
    bool commitBlockList();
    std::string generateBlockId(int blockNumber);
    std::string encodeBase64(const std::string& input);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
};

#endif // AZURE_UPLOADER_H