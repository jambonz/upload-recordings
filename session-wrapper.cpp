#include "session-wrapper.h" // Include the header file for C-compatible declarations
#include "session.h"        // Include the C++ Session class definition

extern "C" {

// Create a new Session instance
void *create_session() {
  try {
    return new Session();
  } catch (const std::exception &e) {
    std::cerr << "Session creation failed: " << e.what() << std::endl;
    return nullptr;
  } catch (...) {
    std::cerr << "Session creation failed, reason unknown "<< std::endl;
    return nullptr;
  }
}

// Destroy an existing Session instance
void destroy_session(void *session) {
  if (session) {
    delete static_cast<Session *>(session);
  }
}

// Add data to the Session buffer
void add_data_to_session(void *session, int isBinary, const char *data, size_t len) {
  if (session) {
    static_cast<Session *>(session)->addData(isBinary, data, len);
  }
}

// Notify the Session that the connection is closed
void notify_session_close(void *session) {
  if (session) {
    static_cast<Session *>(session)->notifyClose();
  }
}

} // extern "C"
