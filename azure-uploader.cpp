#include "azure-uploader.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <stdexcept>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>


// Define the MemoryBuffer structure once
struct MemoryBuffer {
    const char* data;
    size_t size;
};

// Static read callback function for libcurl
extern "C" size_t readCallback(void* ptr, size_t size, size_t nmemb, void* userp) {
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(userp);
    size_t toRead = std::min(mem->size, size * nmemb);

    // Copy data to the buffer and adjust the pointer and remaining size
    std::memcpy(ptr, mem->data, toRead);
    mem->data += toRead;
    mem->size -= toRead;

    return toRead;
}

std::string getCurrentDateTimeRFC1123() {
    char buffer[128];
    std::time_t t = std::time(nullptr);
    std::tm tm;
    gmtime_r(&t, &tm); // Use gmtime_r for thread-safe conversion
    std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    return std::string(buffer);
}

std::vector<unsigned char> decodeBase64(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), input.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Disable newlines in Base64 decoding
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> decodedData(input.size());
    int decodedLength = BIO_read(bio, decodedData.data(), input.size());
    if (decodedLength <= 0) {
        BIO_free_all(bio);
        throw std::runtime_error("Base64 decoding failed.");
    }

    decodedData.resize(decodedLength);
    BIO_free_all(bio);

    return decodedData;
}

AzureUploader::AzureUploader(RecordFileType ftype, const std::string& connectionString, const std::string& containerName)
    : recordFileType_(ftype), containerName_(containerName), curl_(curl_easy_init()), headers_(nullptr) {
    if (!curl_) {
        throw std::runtime_error("Failed to initialize CURL.");
    }

    // Parse the connection string
    std::regex regex(R"(DefaultEndpointsProtocol=(https|http);AccountName=([^;]+);AccountKey=([^;]+);EndpointSuffix=([^;]+))");
    std::smatch match;
    if (!std::regex_match(connectionString, match, regex)) {
        throw std::runtime_error("Invalid connection string format.");
    }

    std::string protocol = match[1];
    accountName_ = match[2];
    accountKey_ = match[3];
    endpointSuffix_ = match[4];

    // Build the base upload URL
    uploadUrl_ = protocol + "://" + accountName_ + ".blob." + endpointSuffix_ + "/" + containerName_ + "/";
    //std::cout << "Full upload URL: " << uploadUrl_ << std::endl;

    // Add standard headers
    headers_ = curl_slist_append(headers_, "Content-Type: application/octet-stream");

   // Set the x-ms-date
    xMsDate_ = getCurrentDateTimeRFC1123();
}

AzureUploader::~AzureUploader() {
    if (headers_) {
        curl_slist_free_all(headers_);
    }
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
}

std::string AzureUploader::generateAuthorizationHeader(const std::string& httpMethod, const std::string& url, const std::string& contentLength) {

    // Extract resource path (e.g., /container/blob)
    std::string resourcePath = url.substr(url.find(".net") + 4); // Get everything after ".net"
    resourcePath = resourcePath.substr(0, resourcePath.find("?")); // Remove query parameters
    //std::cout << "Resource Path: " << resourcePath << std::endl;

    // Extract and sort query parameters (e.g., blockid, comp)
    std::map<std::string, std::string> queryParams;
    std::string queryString = url.substr(url.find("?") + 1);
    std::istringstream queryStream(queryString);
    std::string pair;
    while (std::getline(queryStream, pair, '&')) {
        size_t pos = pair.find('=');
        std::string key = pair.substr(0, pos);
        std::string value = pair.substr(pos + 1);
        queryParams[key] = value;
    }

    // Build the canonicalized resource
    std::ostringstream canonicalizedResource;
    canonicalizedResource << "/" << accountName_ << resourcePath;
    for (const auto& param : queryParams) {
        canonicalizedResource << "\n" << param.first << ":" << param.second;
    }

    // Build the string-to-sign
    std::ostringstream stringToSign;
    stringToSign << httpMethod << "\n"               // HTTP method (e.g., PUT)
                 << "\n"                             // Content-Encoding (empty)
                 << "\n"                             // Content-Language (empty)
                 << contentLength << "\n"            // Content-Length
                 << "\n"                             // Content-MD5 (empty)
                 << "application/octet-stream" << "\n" // Content-Type
                 << "\n"                             // Date (empty, we use x-ms-date instead)
                 << "\n"                             // If-Modified-Since (empty)
                 << "\n"                             // If-Match (empty)
                 << "\n"                             // If-None-Match (empty)
                 << "\n"                             // If-Unmodified-Since (empty)
                 << "\n"                             // Range (empty)
                 << "x-ms-date:" << xMsDate_ << "\n" // x-ms-date header
                 << "x-ms-version:2020-02-10\n"      // x-ms-version header
                 << canonicalizedResource.str();     // Canonicalized resource

    //std::cout << "String to Sign:\n" << stringToSign.str() << std::endl;

    // Decode the account key (base64)
    std::vector<unsigned char> decodedKey = decodeBase64(accountKey_);

    // Generate HMAC-SHA256 signature
    unsigned char hmacResult[EVP_MAX_MD_SIZE];
    unsigned int hmacLength = 0;
    HMAC(EVP_sha256(),
         decodedKey.data(), decodedKey.size(),
         reinterpret_cast<const unsigned char*>(stringToSign.str().c_str()), stringToSign.str().size(),
         hmacResult, &hmacLength);

    // Encode the HMAC result as Base64
    std::string signature = encodeBase64(std::string(reinterpret_cast<char*>(hmacResult), hmacLength));
    //std::cout << "Signature: " << signature << std::endl;

    // Return the Authorization header
    std::string authorizationHeader = "SharedKey " + accountName_ + ":" + signature;
    //std::cout << "Final Authorization Header: " << authorizationHeader << std::endl;
    return authorizationHeader;
}

bool AzureUploader::upload(std::vector<char>& data, bool isFinalChunk) {
    if (upload_failed_) return false;

    if (!upload_in_progress_) {
        if (!initiateUpload()) {
            upload_failed_ = true;
            return false;
        }
        upload_in_progress_ = true;
        blockCount_ = 0; // Initialize block count
    }

    // Upload the current block
    if (!uploadBlock(data.data(), data.size(), ++blockCount_)) {
        std::cerr << "Failed to upload block " << blockCount_ << std::endl;
        upload_failed_ = true;
        return false;
    }

    if (isFinalChunk) {
        if (!finalizeUpload()) {
            upload_failed_ = true;
            return false;
        }
        upload_in_progress_ = false;
    }

    return true;
}

bool AzureUploader::initiateUpload() {
    objectKey_ = createObjectPath(metadata_.call_sid, recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");
    uploadUrl_ += objectKey_;
    //std::cout << "Initiating upload to Azure: " << uploadUrl_ << std::endl;
    return true;
}

bool AzureUploader::uploadBlock(const char* data, size_t size, int blockNumber) {
    try {
        std::string blockId = generateBlockId(blockNumber);
        blockIds_.push_back(blockId);

        std::string blockUrl = uploadUrl_ + "?comp=block&blockid=" + curl_easy_escape(curl_, blockId.c_str(), blockId.length());
        //std::cout << "Uploading Block " << blockNumber << " to URL: " << blockUrl << std::endl;

        std::string contentLength = std::to_string(size);
        std::string authorizationHeader = generateAuthorizationHeader("PUT", blockUrl, contentLength);

        // Reset and configure CURL
        curl_easy_reset(curl_);
        curl_easy_setopt(curl_, CURLOPT_URL, blockUrl.c_str());
        curl_easy_setopt(curl_, CURLOPT_UPLOAD, 1L);

        MemoryBuffer buffer = { data, size };

        curl_easy_setopt(curl_, CURLOPT_READFUNCTION, readCallback);
        curl_easy_setopt(curl_, CURLOPT_READDATA, &buffer);
        curl_easy_setopt(curl_, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(size));
        //curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);

        // Set headers
        struct curl_slist* localHeaders = nullptr;
        localHeaders = curl_slist_append(localHeaders, "Content-Type: application/octet-stream");
        localHeaders = curl_slist_append(localHeaders, ("Authorization: " + authorizationHeader).c_str());
        localHeaders = curl_slist_append(localHeaders, ("x-ms-date: " + xMsDate_).c_str());
        localHeaders = curl_slist_append(localHeaders, "x-ms-version: 2020-02-10");
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, localHeaders);

        // Perform the request
        CURLcode res = curl_easy_perform(curl_);
        curl_slist_free_all(localHeaders);

        // Check for CURL errors
        if (res != CURLE_OK) {
            std::cerr << "Failed to upload block: " << curl_easy_strerror(res) << std::endl;
            return false;
        }

        // Check HTTP response code
        long httpCode = 0;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
        if (httpCode != 201) {
            std::cerr << "Block upload failed with HTTP code: " << httpCode << std::endl;
            return false;
        }

        //std::cout << "Uploaded block " << blockNumber << " successfully." << std::endl;
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "Exception during block upload: " << ex.what() << std::endl;
        return false;
    }
}

bool AzureUploader::finalizeUpload() {
    // Build the XML body for block list
    std::ostringstream xmlBody;
    xmlBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>";
    for (const auto& blockId : blockIds_) {
        xmlBody << "<Latest>" << blockId << "</Latest>";
    }
    xmlBody << "</BlockList>";

    std::string xmlBodyStr = xmlBody.str();
    std::string finalizeUrl = uploadUrl_ + "?comp=blocklist";

    // Generate the Authorization header
    std::string contentLength = std::to_string(xmlBodyStr.length());
    std::string authorizationHeader = generateAuthorizationHeader("PUT", finalizeUrl, contentLength);

    //std::cout << "Finalizing upload to Azure with URL: " << finalizeUrl << std::endl;

    // Set up memory buffer for the XML body
    MemoryBuffer buffer = { xmlBodyStr.c_str(), xmlBodyStr.length() };

    // Reset curl for a clean configuration
    curl_easy_reset(curl_);

    // Set the URL and HTTP method (PUT)
    curl_easy_setopt(curl_, CURLOPT_URL, finalizeUrl.c_str());
    curl_easy_setopt(curl_, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl_, CURLOPT_READFUNCTION, readCallback);
    curl_easy_setopt(curl_, CURLOPT_READDATA, &buffer);
    curl_easy_setopt(curl_, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(xmlBodyStr.length()));
    //curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);

    // Set headers
    struct curl_slist* localHeaders = nullptr;
    localHeaders = curl_slist_append(localHeaders, "Content-Type: application/octet-stream");
    localHeaders = curl_slist_append(localHeaders, ("Authorization: " + authorizationHeader).c_str());
    localHeaders = curl_slist_append(localHeaders, ("x-ms-date: " + xMsDate_).c_str());
    localHeaders = curl_slist_append(localHeaders, "x-ms-version: 2020-02-10");
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, localHeaders);

    // Perform the request
    CURLcode res = curl_easy_perform(curl_);
    curl_slist_free_all(localHeaders);

    if (res != CURLE_OK) {
        std::cerr << "Failed to finalize upload: " << curl_easy_strerror(res) << std::endl;
        return false;
    }

    // Check HTTP response code
    long httpCode = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode != 201) {
        std::cerr << "Finalize upload failed with HTTP code: " << httpCode << std::endl;
        return false;
    }

    //std::cout << "Upload finalized successfully." << std::endl;
    return true;
}

std::string AzureUploader::generateBlockId(int blockNumber) {
    std::ostringstream oss;
    oss << "block-" << std::setw(6) << std::setfill('0') << blockNumber;
    return encodeBase64(oss.str());
}

std::string AzureUploader::encodeBase64(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encodedData;
}

size_t AzureUploader::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    (void)contents;
    (void)userp;
    return size * nmemb;
}