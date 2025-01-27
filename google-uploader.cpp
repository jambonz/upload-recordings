#include "google-uploader.h"
#include "upload-utils.h"
#include <aws/core/external/cjson/cJSON.h>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>

std::string encodeBase64(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Encode without newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encodedData;
}

std::string encodeBase64URL(const std::string& input) {
    std::string base64 = encodeBase64(input);
    std::replace(base64.begin(), base64.end(), '+', '-');
    std::replace(base64.begin(), base64.end(), '/', '_');
    base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());
    return base64;
}

std::string signWithPrivateKey(const std::string& message, const std::string& privateKeyPem) {
    BIO* bio = BIO_new_mem_buf(privateKeyPem.data(), privateKeyPem.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    // Load the private key
    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!privateKey) {
        throw std::runtime_error("Failed to load private key");
    }

    // Create a signing context
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(mdCtx, nullptr, EVP_sha256(), nullptr, privateKey) <= 0) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to initialize digest sign");
    }

    // Perform signing
    if (EVP_DigestSignUpdate(mdCtx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to update digest sign");
    }

    size_t signatureLen = 0;
    if (EVP_DigestSignFinal(mdCtx, nullptr, &signatureLen) <= 0) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to finalize digest sign");
    }

    std::vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(mdCtx, signature.data(), &signatureLen) <= 0) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to retrieve signature");
    }

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(privateKey);

    // Convert signature to Base64
    return encodeBase64URL(std::string(signature.begin(), signature.end()));
}

GoogleUploader::GoogleUploader(std::shared_ptr<spdlog::logger> log, RecordFileType ftype, const std::string& bucketName,
  const std::string& clientEmail, const std::string& privateKey, const std::string& tokenUri) : 
    recordFileType_(ftype), clientEmail_(clientEmail), privateKey_(privateKey), tokenUri_(tokenUri), 
    bucketName_(bucketName), curl_(curl_easy_init()), headers_(nullptr) {

    setLogger(log);

    log_->debug("google bucket: {}", bucketName_);

    if (!curl_) {
        throw std::runtime_error("Failed to initialize CURL.");
    }
    if (privateKey_.empty() || clientEmail_.empty() || tokenUri_.empty()) {
      log_->error("Missing required Google credentials.");
      throw std::runtime_error("Missing required Google credentials.");
    }
    
}

GoogleUploader::~GoogleUploader() {
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
    if (headers_) {
        curl_slist_free_all(headers_);
    }
}

// Static header callback function
size_t GoogleUploader::writeHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t totalSize = size * nitems;
    std::string header(buffer, totalSize);

    if (header.find("location: ") == 0) { // Look for 'location' header
        std::string* sessionUrl = static_cast<std::string*>(userdata);
        *sessionUrl = header.substr(10); // Extract everything after 'location: '
        sessionUrl->erase(sessionUrl->find_last_not_of(" \r\n") + 1); // Trim trailing whitespace
    }

    return totalSize;
}

bool GoogleUploader::upload(std::vector<char>& data, bool isFinalChunk) {
    if (!upload_in_progress_) {
        objectKey_ = createObjectPath(metadata_.call_sid, recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");
        uploadSessionUrl_ = initiateResumableUpload();
        if (uploadSessionUrl_.empty()) {
            log_->error("Failed to initiate resumable upload.");
            return false;
        }
        upload_in_progress_ = true;
    }

    if (!uploadChunk(data.data(), data.size())) {
        log_->error("Failed to upload data ");
        upload_failed_ = true;
        return false;
    }

    if (isFinalChunk) {
        finalizeUpload();
        upload_in_progress_ = false;
    }

    return true;
}

std::string GoogleUploader::generateOAuthToken() {
    // Create JWT header and payload
    std::string header = R"({"alg":"RS256","typ":"JWT"})";
    std::ostringstream payload;
    payload << R"({"iss":")" << clientEmail_
            << R"(","scope":"https://www.googleapis.com/auth/devstorage.read_write",)"
            << R"("aud":")" << tokenUri_
            << R"(","exp":)" << std::time(nullptr) + 3600
            << R"(,"iat":)" << std::time(nullptr) << "}";


    // Base64-encode header and payload
    std::string encodedHeader = encodeBase64URL(header);
    std::string encodedPayload = encodeBase64URL(payload.str());
    std::string signatureInput = encodedHeader + "." + encodedPayload;

    // Sign the JWT
    std::string signature = signWithPrivateKey(signatureInput, privateKey_);
    std::string signedJwt = signatureInput + "." +signature; // Concatenate all three parts

    // Exchange JWT for OAuth token
    std::string token;
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string postData = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + signedJwt;
        curl_easy_setopt(curl, CURLOPT_URL, tokenUri_.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &token);
        curl_easy_setopt(curl_, CURLOPT_VERBOSE, 0L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_->error("Failed to fetch OAuth token: {}", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            return "";
        }
        curl_easy_cleanup(curl);
    }
    else {
      log_->error("Failed to initialize CURL.");
      return "";  // Exit early if CURL couldn't be initialized
    }

    // Extract the token from the JSON response
    if (token.empty()) {
        log_->error("OAuth token response is empty.");
        return "";  // Exit early if no response was received
    }

    cJSON* responseJson = cJSON_AS4CPP_Parse(token.c_str());
    if (!responseJson) {
        log_->error("Failed to parse OAuth token response JSON: {}", token);
        return "";  // Exit early if JSON parsing failed
    }

    // Extract the token from the JSON response
    cJSON* accessTokenItem = cJSON_AS4CPP_GetObjectItem(responseJson, "access_token");
    std::string accessToken;

    if (accessTokenItem && cJSON_AS4CPP_IsString(accessTokenItem)) {
        accessToken = accessTokenItem->valuestring;
    } else {
        log_->error("OAuth token response does not contain a valid access token: {}", token);
    }

    cJSON_AS4CPP_Delete(responseJson);

    if (accessToken.empty()) {
        log_->error("Failed to retrieve access token from response.");
        return "";  // Exit early if no valid token was found
    }

    return accessToken;
}

std::string GoogleUploader::initiateResumableUpload() {
    // Step 1: Generate OAuth token
    accessToken_ = generateOAuthToken();
    if (accessToken_.empty()) {
        return "";
    }

    // Step 2: Construct the initial resumable upload URL
    std::string url = "https://storage.googleapis.com/upload/storage/v1/b/" + bucketName_ + "/o?uploadType=resumable&name=" + objectKey_;
    std::string sessionUrl; // This will store the 'location' header
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &GoogleUploader::writeHeaderCallback); // Use the static method
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &sessionUrl); // Pass session URL as user data
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

        // Set up the headers
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("Authorization: Bearer " + accessToken_).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json; charset=UTF-8");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Step 3: Perform the POST request
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_->error("Failed to initiate resumable upload: {}", curl_easy_strerror(res));
            sessionUrl.clear(); // Clear session URL to indicate failure
        }
        // Cleanup
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    } else {
        log_->error("Failed to initialize CURL.");
        return "";
    }

    // Step 4: Validate the session URL
    if (sessionUrl.empty()) {
        log_->error("Error: Resumable upload session URL not received.");
    }

    return sessionUrl;
}

bool GoogleUploader::uploadChunk(const char* data, size_t size) {
    if (uploadSessionUrl_.empty()) {
      log_->error("Upload session URL is empty.");
      return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    MemoryBuffer buffer = { data, size };
    std::string responseBody; // To capture response data.

    curl_easy_setopt(curl, CURLOPT_URL, uploadSessionUrl_.c_str());
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(size));
    curl_easy_setopt(curl_, CURLOPT_VERBOSE, 0L);

    // Set the write callback to capture the response body.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_->error("Failed to upload chunk: {}", curl_easy_strerror(res));
    }
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return res == CURLE_OK;
}

bool GoogleUploader::finalizeUpload() {
  log_->info("File uploaded successfully: {}", objectKey_);
  return true;
}

size_t GoogleUploader::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::string* str = static_cast<std::string*>(userp);
    str->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}
