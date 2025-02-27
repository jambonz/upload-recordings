#include "session-wrapper.h" // Include the header file for C-compatible declarations
#include "connection-manager.h"  // Include the connection manager

extern "C" {

// Create a new Session instance via the connection manager
void *create_session() {
  try {
    return ConnectionManager::getInstance().createSession();
  } catch (const std::exception &e) {
    std::cerr << "Session creation failed: " << e.what() << std::endl;
    return nullptr;
  } catch (...) {
    std::cerr << "Session creation failed, reason unknown "<< std::endl;
    return nullptr;
  }
}

// Add data to the Session buffer
void add_data_to_session(void *session, int isBinary, const char *data, size_t len) {
  auto p = static_cast<Session*>(session)->shared_from_this();
  if (session) {
    static_cast<Session *>(session)->addData(isBinary, data, len);
  }
}

// Notify the Session that the connection is closed
void notify_session_close(void *session) {
  auto p = static_cast<Session*>(session)->shared_from_this();
  if (session) {
    static_cast<Session *>(session)->notifyClose();
  }
}

} // extern "C"
