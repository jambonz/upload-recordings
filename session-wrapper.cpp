#include "session-wrapper.h" // Include the header file for C-compatible declarations
#include "session.h"        // Include the C++ Session class definition

extern "C" {

// Create a new Session instance
void *create_session() {
  std::cout << "Creating a new session\n";
  return new Session();
}

// Destroy an existing Session instance
void destroy_session(void *session) {
  std::cout << "Destroying a session\n";
  delete static_cast<Session *>(session);
}

// Add data to the Session buffer
void add_data_to_session(void *session, int isBinary, const char *data, size_t len) {
  static_cast<Session *>(session)->addData(isBinary, data, len);
}

// Notify the Session that the connection is closed
void notify_session_close(void *session) {
  std::cout << "Notifying session of close\n";
  static_cast<Session *>(session)->notifyClose();
}

} // extern "C"
