#include "session.h"

// Static member initialization
std::once_flag Session::initFlag_;
std::string Session::uploadFolder_;
CryptoHelper Session::cryptoHelper_ = CryptoHelper();

void Session::addData(int isBinary, const char *data, size_t len) {
  {
    std::unique_lock<std::mutex> lock(mutex_);

    // Check for overflow
    if (buffer_size_ + len > MAX_BUFFER_SIZE) {
        std::cerr << "Buffer overflow: dropping data\n";
        return;
    }

    if (isBinary) {
      //std::cout << "Received " << len << " bytes of binary data\n";

      // Copy data directly to the preallocated buffer
      std::memcpy(buffer_.data() + buffer_size_, data, len);
      buffer_size_ += len;

      // Notify the worker thread if the buffer size reaches the threshold
      if (buffer_size_ >= BUFFER_PROCESS_SIZE) {
          cv_.notify_all();
      }
    } 
    else if (!json_metadata_) {
      tmp_.append(data, len);
      cJSON *json = cJSON_AS4CPP_Parse(tmp_.c_str());
      if (json != nullptr) {
        json_metadata_ = json;
        metadata_received_ = true;
        std::cout << "Valid JSON metadata received: " << tmp_ << std::endl;

        cv_.notify_all(); // Notify the worker thread to process metadata
      }
    }
    else {
      std::cerr << "Unexpected text frame after metadata: " << std::string(data, len) << std::endl;
    }
  }
}

void Session::notifyClose() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
  }
  cv_.notify_all();
}

