#include "upload-utils.h"

extern "C" size_t readCallback(void* ptr, size_t size, size_t nmemb, void* userp) {
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(userp);
    size_t toRead = std::min(mem->size, size * nmemb);

    // Copy data to the buffer and adjust the pointer and remaining size
    std::memcpy(ptr, mem->data, toRead);
    mem->data += toRead;
    mem->size -= toRead;

    return toRead;
}
