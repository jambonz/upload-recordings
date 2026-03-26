#ifndef SESSION_WRAPPER_H
#define SESSION_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// Create a new Session instance
void *create_session();

// Add data to the Session buffer
void add_data_to_session(void *session, int isBinary, const char *data, size_t len);

// Notify the Session that the connection is closed
void notify_session_close(void *session);

#ifdef __cplusplus
}
#endif

#endif // SESSION_WRAPPER_H
