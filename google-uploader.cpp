#include "google-uploader.h"
#include "upload-utils.h"
#include "wav-header.h" 

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

GoogleUploader::GoogleUploader(const std::shared_ptr<Session>& session, std::shared_ptr<spdlog::logger> log,
    std::string& uploadFolder,
    RecordFileType ftype,
    const std::string& bucketName,
    const std::string& clientEmail, 
    const std::string& privateKey, 
    const std::string& tokenUri) : StorageUploader(session), recordFileType_(ftype), clientEmail_(clientEmail), privateKey_(privateKey), tokenUri_(tokenUri), 
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

    // Create a temporary file for buffering data
    createTempFile(uploadFolder);
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
  if (!tempFile_.is_open()) {
    log_->error("Temporary file is not open. Upload failed.");
    upload_failed_ = true;
    return false;
  }

  // Append the data to the temporary file.
  tempFile_.write(data.data(), data.size());
  if (!tempFile_.good()) {
    log_->error("Error writing to temporary file: {}", tempFilePath_);
    upload_failed_ = true;
    return false;
  }
  tempFile_.flush();
  log_->info("Buffered {} bytes to temporary file {}.", data.size(), tempFilePath_);

  if (isFinalChunk) {
    finalizeUpload();
  }
  return true;
}

void GoogleUploader::finalizeUpload() {
    objectKey_ = createObjectPath(metadata_.call_sid, recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");

  // Close the buffer file if it is still open.
  if (tempFile_.is_open()) {
    tempFile_.close();
  }
  
    // if this is a WAV file, we need to prepend a wave header
    std::string finalFilePath = tempFilePath_;
  if (recordFileType_ == RecordFileType::WAV) {
    char wavTempFilePath[] = "/tmp/uploads/wavfile-XXXXXX";
    int wavTempFd = mkstemp(wavTempFilePath);
    if (wavTempFd == -1) {
      log_->error("Failed to create unique WAV temporary file using mkstemp: {}", std::strerror(errno));
      upload_failed_ = true;
      cleanupTempFile();
      return;
    }
    std::ofstream wavTempFile(wavTempFilePath, std::ios::binary);
    if (!wavTempFile) {
      log_->error("Failed to open WAV temporary file: {}", wavTempFilePath);
      close(wavTempFd);
      upload_failed_ = true;
      cleanupTempFile();
      return;
    }
    // Get the size of the raw audio data.
    auto audioDataSize = std::filesystem::file_size(tempFilePath_);
    // Generate the WAV header.
    WavHeaderPrepender headerPrepender(8000, 2, 16); // sample rate, channels, bit depth
    std::vector<char> wavHeader = headerPrepender.createHeader(static_cast<uint32_t>(audioDataSize));

    // Write the header.
    wavTempFile.write(wavHeader.data(), wavHeader.size());
    if (!wavTempFile.good()) {
      log_->error("Failed to write WAV header to temporary file: {}", wavTempFilePath);
      close(wavTempFd);
      upload_failed_ = true;
      cleanupTempFile();
      return;
    }
    // Append the raw audio data.
    std::ifstream rawAudioFile(tempFilePath_, std::ios::binary);
    if (!rawAudioFile) {
      log_->error("Failed to open raw audio temporary file: {}", tempFilePath_);
      close(wavTempFd);
      upload_failed_ = true;
      cleanupTempFile();
      return;
    }
    wavTempFile << rawAudioFile.rdbuf();
    wavTempFile.close();
    rawAudioFile.close();
    close(wavTempFd);
    log_->info("WAV file created with header at: {}", wavTempFilePath);
    finalFilePath = wavTempFilePath;
  }

  // Initiate a resumable upload session.
  std::string sessionUrl = initiateResumableUpload();
  if (sessionUrl.empty()) {
    log_->error("Failed to initiate resumable upload session.");
    upload_failed_ = true;
    cleanupTempFile();
    return;
  }

  // Upload the file (which might be very large) in chunks.
  bool success = uploadFileInChunks(finalFilePath, sessionUrl);
  if (!success) {
    log_->error("Failed to upload file in chunks: {}", finalFilePath);
    upload_failed_ = true;
  } else {
    log_->info("File uploaded successfully: {} to {}", finalFilePath, objectKey_);
  }

  // If we created a new WAV file, delete it.
  if (recordFileType_ == RecordFileType::WAV) {
    std::remove(finalFilePath.c_str());
  }
  cleanupTempFile();
}

bool GoogleUploader::uploadFileInChunks(const std::string &filePath, const std::string &sessionUrl) {
  std::ifstream file(filePath, std::ios::binary);
  if (!file) {
    log_->error("Failed to open file for uploading: {}", filePath);
    return false;
  }
  file.seekg(0, std::ios::end);
  size_t totalSize = file.tellg();
  file.seekg(0, std::ios::beg);
  const size_t CHUNK_SIZE = 8 * 1024 * 1024; // 8 MB per chunk
  size_t offset = 0;
  while (offset < totalSize) {
    size_t currentChunkSize = std::min(CHUNK_SIZE, totalSize - offset);
    std::vector<char> buffer(currentChunkSize);
    file.read(buffer.data(), currentChunkSize);
    if (!file) {
      log_->error("Failed to read chunk from file: {}", filePath);
      return false;
    }
    bool chunkSuccess = uploadChunkWithRange(sessionUrl, buffer.data(), currentChunkSize, offset, totalSize);
    if (!chunkSuccess) {
      log_->error("Failed to upload chunk at offset {}", offset);
      return false;
    }
    offset += currentChunkSize;
  }
  return true;
}

bool GoogleUploader::uploadChunkWithRange(const std::string &sessionUrl,
                                            const char* data,
                                            size_t dataSize,
                                            size_t offset,
                                            size_t totalSize) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    log_->error("CURL initialization failed.");
    return false;
  }
  MemoryBuffer buffer { data, dataSize };
  std::string responseBody;
  curl_easy_setopt(curl, CURLOPT_URL, sessionUrl.c_str());
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
  curl_easy_setopt(curl, CURLOPT_READDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(dataSize));

  // Construct the Content-Range header.
  std::ostringstream rangeStream;
  size_t endOffset = offset + dataSize - 1;
  rangeStream << "Content-Range: bytes " << offset << "-" << endOffset << "/" << totalSize;
  std::string rangeHeader = rangeStream.str();

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, rangeHeader.c_str());
  headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    log_->error("Failed to upload chunk (offset {}): {}", offset, curl_easy_strerror(res));
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return false;
  }
  long response_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  bool success = false;
  // For intermediate chunks, Google expects a 308 (Resume Incomplete).
  // For the final chunk, a 200 or 201 is expected.
  if (offset + dataSize < totalSize) {
    if (response_code == 308) {
      success = true;
    } else {
      log_->error("Unexpected response code for intermediate chunk: {}", response_code);
    }
  } else {
    if (response_code == 200 || response_code == 201) {
      success = true;
    } else {
      log_->error("Unexpected response code for final chunk: {}", response_code);
    }
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  return success;
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

size_t GoogleUploader::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::string* str = static_cast<std::string*>(userp);
    str->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}
