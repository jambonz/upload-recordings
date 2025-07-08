#include "azure-uploader.h"
#include "upload-utils.h"
#include "wav-header.h"
#include "streaming-mp3-encoder.h"

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

AzureUploader::AzureUploader(const std::shared_ptr<Session>& session, std::shared_ptr<spdlog::logger> log, std::string& uploadFolder, RecordFileType ftype, 
  const std::string& connectionString, const std::string& containerName)
  : StorageUploader(session), recordFileType_(ftype),
      containerName_(containerName),
      curl_(curl_easy_init()),
      headers_(nullptr),
      blockSize_(4 * 1024 * 1024)  
{
  if (!curl_) {
      throw std::runtime_error("Failed to initialize CURL.");
  }
  setLogger(log);

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
  uploadUrlBase_ = protocol + "://" + accountName_ + ".blob." + endpointSuffix_ + "/" + containerName_ + "/";

  // Add standard headers
  headers_ = curl_slist_append(headers_, "Content-Type: application/octet-stream");

  // Set the x-ms-date
  xMsDate_ = getCurrentDateTimeRFC1123();

  createTempFile(uploadFolder);
}

AzureUploader::~AzureUploader() {
    if (headers_) {
      curl_slist_free_all(headers_);
    }
    if (curl_) {
      curl_easy_cleanup(curl_);
    }
}

bool AzureUploader::upload(std::vector<char>& data, bool isFinalChunk) {
  if (upload_failed_) return false;

  if (!tempFile_.is_open()) {
      log_->error("Temporary file is not open. Upload failed.");
      upload_failed_ = true;
      cleanupTempFile();
      return false;
  }

  // Write data to temporary file.
  tempFile_.write(data.data(), data.size());
  if (!tempFile_.good()) {
      log_->error("Error writing to temporary file: {}", tempFilePath_);
      upload_failed_ = true;
      cleanupTempFile();
      return false;
  }
  tempFile_.flush();
  log_->info("Buffered {} bytes to temporary file {}.", data.size(), tempFilePath_);

  if (isFinalChunk) {
    tempFile_.close();
    std::string finalFilePath = tempFilePath_;

    objectKey_ = createObjectPath(metadata_.call_sid,
                              recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");

    // Handle different file types
    if (recordFileType_ == RecordFileType::MP3) {
      // For MP3, we need to encode the raw PCM data using streaming
      log_->info("Encoding PCM data to MP3 format using streaming");
      
      // Create a unique temporary file for the MP3
      char mp3TempFilePath[] = "/tmp/azure-mp3file-XXXXXX";
      int mp3TempFd = mkstemp(mp3TempFilePath);
      if (mp3TempFd == -1) {
        log_->error("Failed to create unique MP3 temporary file: {}", std::strerror(errno));
        upload_failed_ = true;
        cleanupTempFile();
        return false;
      }
      close(mp3TempFd); // Close the descriptor as we'll use the encoder's file methods
      
      try {
        // Create streaming MP3 encoder with metadata parameters
        // Using 2 channels and 128 kbps as before
        StreamingMp3Encoder encoder(metadata_.sample_rate, 2, 128);
        
        // Get the size of the PCM file for logging
        auto pcmFileSize = std::filesystem::file_size(tempFilePath_);
        log_->info("Starting streaming MP3 encoding of {} bytes of PCM data", pcmFileSize);
        
        // Encode the file using streaming (reads and writes in chunks)
        encoder.encodeFile(tempFilePath_, mp3TempFilePath);
        
        // Get the size of the resulting MP3 file
        auto mp3FileSize = std::filesystem::file_size(mp3TempFilePath);
        
        // Update the final file path to point to the MP3 file
        finalFilePath = mp3TempFilePath;
        log_->info("Successfully encoded {} bytes of PCM to {} bytes of MP3", pcmFileSize, mp3FileSize);
        
      } catch (const std::exception& e) {
        log_->error("MP3 encoding failed: {}", e.what());
        std::remove(mp3TempFilePath);
        upload_failed_ = true;
        cleanupTempFile();
        return false;
      }
    }
    else if (recordFileType_ == RecordFileType::WAV) {
      char wavTempFilePath[] = "/tmp/azure-wavfile-XXXXXX";
      int wavTempFd = mkstemp(wavTempFilePath);
      if (wavTempFd == -1) {
        log_->error("Failed to create unique WAV temporary file: {}", std::strerror(errno));
        upload_failed_ = true;
        cleanupTempFile();
        return false;
      }
      std::ofstream wavTempFile(wavTempFilePath, std::ios::binary);
      if (!wavTempFile) {
        log_->error("Failed to open WAV temporary file: {}", wavTempFilePath);
        close(wavTempFd);
        upload_failed_ = true;
        cleanupTempFile();
        return false;
      }
      // Determine the size of the raw audio.
      auto audioDataSize = std::filesystem::file_size(tempFilePath_);
      // Generate the WAV header (using your existing header class).
      WavHeaderPrepender headerPrepender(8000, 2, 16); // sample rate, channels, bit depth
      std::vector<char> wavHeader = headerPrepender.createHeader(static_cast<uint32_t>(audioDataSize));
      // Write header then raw audio.
      wavTempFile.write(wavHeader.data(), wavHeader.size());
      if (!wavTempFile.good()) {
        log_->error("Failed to write WAV header to temporary file: {}", wavTempFilePath);
        close(wavTempFd);
        upload_failed_ = true;
        cleanupTempFile();
        return false;
      }
      std::ifstream rawAudioFile(tempFilePath_, std::ios::binary);
      if (!rawAudioFile) {
        log_->error("Failed to open raw audio temporary file: {}", tempFilePath_);
        close(wavTempFd);
        upload_failed_ = true;
        cleanupTempFile();
        return false;
      }
      wavTempFile << rawAudioFile.rdbuf();
      wavTempFile.close();
      rawAudioFile.close();
      close(wavTempFd);
      log_->info("WAV file created with header at: {}", wavTempFilePath);
      finalFilePath = wavTempFilePath;
    }

    // Build the full upload URL.
    uploadUrl_ = uploadUrlBase_ + objectKey_;

    // Clear any previous block IDs.
    blockIds_.clear();

    // Upload the file in blocks.
    if (!uploadFileInBlocks(finalFilePath)) {
      log_->error("Failed to upload file in blocks: {}", finalFilePath);
      upload_failed_ = true;
      cleanupTempFile();
      return false;
    }
    // Commit the block list.
    if (!commitBlockList()) {
      log_->error("Failed to commit block list for blob: {}", objectKey_);
      upload_failed_ = true;
      cleanupTempFile();
      return false;
    }

    log_->info("File uploaded successfully: {}", objectKey_);
    // If we created a new WAV or MP3 file, delete it.
    if (recordFileType_ == RecordFileType::WAV || recordFileType_ == RecordFileType::MP3) {
      std::remove(finalFilePath.c_str());
    }
    // Clean up the buffering temp file.
    cleanupTempFile();
    upload_in_progress_ = false;
  }

  return true;
}

bool AzureUploader::uploadFileInBlocks(const std::string &filePath) {
  std::ifstream file(filePath, std::ios::binary);
  if (!file) {
    log_->error("Failed to open file for block upload: {}", filePath);
    return false;
  }
  // Determine total file size.
  file.seekg(0, std::ios::end);
  size_t totalSize = file.tellg();
  file.seekg(0, std::ios::beg);

  size_t offset = 0;
  int blockNumber = 0;
  std::vector<char> buffer;
  buffer.resize(blockSize_);

  while (offset < totalSize) {
    size_t currentBlockSize = std::min(blockSize_, totalSize - offset);
    file.read(buffer.data(), currentBlockSize);
    if (!file) {
      log_->error("Error reading file block from: {}", filePath);
      return false;
    }
    blockNumber++;
    // Generate a block ID.
    std::string blockId = generateBlockId(blockNumber);
    blockIds_.push_back(blockId);
    // Upload this block.
    if (!uploadBlock(buffer.data(), currentBlockSize, blockId)) {
      log_->error("Failed to upload block {} at offset {}", blockNumber, offset);
      return false;
    }
    offset += currentBlockSize;
  }
  return true;
}

bool AzureUploader::uploadBlock(const char* data, size_t size, const std::string &blockId) {
  try {
    // Build the block upload URL.
    // Note: curl_easy_escape is used to URL-encode the blockId.
    char* encodedBlockId = curl_easy_escape(curl_, blockId.c_str(), blockId.length());
    std::string blockUrl = uploadUrl_ + "?comp=block&blockid=" + std::string(encodedBlockId);
    curl_free(encodedBlockId);

    std::string contentLength = std::to_string(size);
    std::string authorizationHeader = generateAuthorizationHeader("PUT", blockUrl, contentLength);

    // Reset and configure CURL.
    curl_easy_reset(curl_);
    curl_easy_setopt(curl_, CURLOPT_URL, blockUrl.c_str());
    curl_easy_setopt(curl_, CURLOPT_UPLOAD, 1L);

    MemoryBuffer buffer = { data, size };
    curl_easy_setopt(curl_, CURLOPT_READFUNCTION, readCallback);
    curl_easy_setopt(curl_, CURLOPT_READDATA, &buffer);
    curl_easy_setopt(curl_, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(size));
    curl_easy_setopt(curl_, CURLOPT_VERBOSE, 0L);

    // Set headers.
    struct curl_slist* localHeaders = nullptr;
    localHeaders = curl_slist_append(localHeaders, "Content-Type: application/octet-stream");
    localHeaders = curl_slist_append(localHeaders, ("Authorization: " + authorizationHeader).c_str());
    localHeaders = curl_slist_append(localHeaders, ("x-ms-date: " + xMsDate_).c_str());
    localHeaders = curl_slist_append(localHeaders, "x-ms-version: 2020-02-10");
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, localHeaders);

    // Perform the block upload.
    CURLcode res = curl_easy_perform(curl_);
    curl_slist_free_all(localHeaders);

    if (res != CURLE_OK) {
      log_->error("Failed to upload block ({}): {}", blockId, curl_easy_strerror(res));
      return false;
    }

    long httpCode = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode != 201) {
      log_->error("Block upload for {} failed with HTTP code: {}", blockId, httpCode);
      return false;
    }
    return true;
  } catch (const std::exception& ex) {
    log_->error("Exception during block upload: {}", ex.what());
    return false;
  }
}

bool AzureUploader::commitBlockList() {
  std::ostringstream xmlBody;
  xmlBody << "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>";
  for (const auto& blockId : blockIds_) {
    xmlBody << "<Latest>" << blockId << "</Latest>";
  }
  xmlBody << "</BlockList>";
  std::string xmlBodyStr = xmlBody.str();

  std::string finalizeUrl = uploadUrl_ + "?comp=blocklist";
  std::string contentLength = std::to_string(xmlBodyStr.length());
  std::string authorizationHeader = generateAuthorizationHeader("PUT", finalizeUrl, contentLength);

  MemoryBuffer buffer = { xmlBodyStr.c_str(), xmlBodyStr.length() };

  curl_easy_reset(curl_);
  curl_easy_setopt(curl_, CURLOPT_URL, finalizeUrl.c_str());
  curl_easy_setopt(curl_, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl_, CURLOPT_READFUNCTION, readCallback);
  curl_easy_setopt(curl_, CURLOPT_READDATA, &buffer);
  curl_easy_setopt(curl_, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(xmlBodyStr.length()));
  curl_easy_setopt(curl_, CURLOPT_VERBOSE, 0L);

  struct curl_slist* localHeaders = nullptr;
  localHeaders = curl_slist_append(localHeaders, "Content-Type: application/octet-stream");
  localHeaders = curl_slist_append(localHeaders, ("Authorization: " + authorizationHeader).c_str());
  localHeaders = curl_slist_append(localHeaders, ("x-ms-date: " + xMsDate_).c_str());
  localHeaders = curl_slist_append(localHeaders, "x-ms-version: 2020-02-10");
  curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, localHeaders);

  CURLcode res = curl_easy_perform(curl_);
  curl_slist_free_all(localHeaders);

  if (res != CURLE_OK) {
    log_->error("Failed to commit block list: {}", curl_easy_strerror(res));
    return false;
  }

  long httpCode = 0;
  curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpCode);
  if (httpCode != 201) {
    log_->error("Finalize (commit block list) failed with HTTP code: {}", httpCode);
    return false;
  }

  return true;
}

std::string AzureUploader::generateBlockId(int blockNumber) {
    std::ostringstream oss;
    oss << "block-" << std::setw(6) << std::setfill('0') << blockNumber;
    return encodeBase64(oss.str());
}

std::string AzureUploader::generateAuthorizationHeader(const std::string& httpMethod, const std::string& url, const std::string& contentLength) {

    // Extract resource path (e.g., /container/blob)
    std::string resourcePath = url.substr(url.find(".net") + 4); // Get everything after ".net"
    resourcePath = resourcePath.substr(0, resourcePath.find("?")); // Remove query parameters

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

    // Return the Authorization header
    std::string authorizationHeader = "SharedKey " + accountName_ + ":" + signature;
    return authorizationHeader;
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