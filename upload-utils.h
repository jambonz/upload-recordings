#ifndef UPLOAD_UTILS_H
#define UPLOAD_UTILS_H

#include <cstddef> // For size_t
#include <cstring> // For std::memcpy
#include <algorithm> // For std::min

// Define the MemoryBuffer structure
struct MemoryBuffer {
    const char* data;
    size_t size;
};

// Declare the read callback function
extern "C" size_t readCallback(void* ptr, size_t size, size_t nmemb, void* userp);

#endif // UPLOAD_UTILS_H