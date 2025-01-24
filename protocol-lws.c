#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "session-wrapper.h" 

#include <string.h>

/* Forward declaration of the callback function */
static int callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len);

/* Define the per-session data struct */
struct per_session_data__minimal {
    struct lws *wsi;
    void *session;
};

/* Define the macro after declaring the callback function and session struct */
#define LWS_PLUGIN_PROTOCOL_JAMBONZ \
    { \
        "audio.jambonz.org", \
        callback_minimal, \
        sizeof(struct per_session_data__minimal), \
        128, \
        0, NULL, 0 \
    }

/* Protocols array */
const struct lws_protocols protocols[] = {
    { "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
    LWS_PLUGIN_PROTOCOL_JAMBONZ,
    LWS_PROTOCOL_LIST_TERM
};

/* one of these is created for each vhost our protocol is used with */
struct per_vhost_data__minimal {
    struct lws_context *context;
    struct lws_vhost *vhost;
    const struct lws_protocols *protocol;
};

static int validate_basic_auth(const char *auth_header) {
  const char *expected_username = getenv("BASIC_AUTH_USERNAME");
  const char *expected_password = getenv("BASIC_AUTH_PASSWORD");

  if (!expected_username || !expected_password) {
      lwsl_err("Environment variables BASIC_AUTH_USERNAME or BASIC_AUTH_PASSWORD are not set\n");
      return false;
  }

  // Combine username and password into the expected credentials format
  char expected_creds[256];
  snprintf(expected_creds, sizeof(expected_creds), "%s:%s", expected_username, expected_password);

  if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0) {
      return false;
  }

  // Decode the Base64 part of the header
  const char *base64_creds = auth_header + 6;
  char decoded_creds[256];
  size_t decoded_len = lws_b64_decode_string(base64_creds, decoded_creds, sizeof(decoded_creds));
  if (decoded_len < 0) {
      return false; // Invalid Base64
  }

  // Null-terminate the decoded credentials
  decoded_creds[decoded_len] = '\0';

  // Check against expected credentials
  return strcmp(decoded_creds, expected_creds) == 0;
}

static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
                 void *user, void *in, size_t len)
{
    struct per_session_data__minimal *pss =
        (struct per_session_data__minimal *)user;
    struct per_vhost_data__minimal *vhd =
        (struct per_vhost_data__minimal *)
        lws_protocol_vh_priv_get(lws_get_vhost(wsi),
                                 lws_get_protocol(wsi));
    int m;

    switch (reason) {
    case LWS_CALLBACK_PROTOCOL_INIT:
        vhd = (struct per_vhost_data__minimal *)
            lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
                                        lws_get_protocol(wsi),
                                        sizeof(struct per_vhost_data__minimal));
        vhd->context = lws_get_context(wsi);
        vhd->protocol = lws_get_protocol(wsi);
        vhd->vhost = lws_get_vhost(wsi);
        break;

    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
      char auth_header[256];
      int header_len = lws_hdr_copy(wsi, auth_header, sizeof(auth_header), WSI_TOKEN_HTTP_AUTHORIZATION);

      if (header_len <= 0) {
          lwsl_warn("Authorization header not found\n");
          return -1; // Deny connection
      }

      if (!validate_basic_auth(auth_header)) {
          lwsl_warn("Unauthorized access attempt\n");
          return -1; // Deny connection
      }
      break;
    }

    case LWS_CALLBACK_ESTABLISHED:
        pss->session = create_session();
        break;

    case LWS_CALLBACK_CLOSED:
        if (pss->session) {
            notify_session_close(pss->session);
            destroy_session(pss->session);
            pss->session = NULL;
        }
        break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
        /* we never write anything back to client */
        break;

    case LWS_CALLBACK_RECEIVE:
        if (pss->session) {
          int isBinary = lws_frame_is_binary(wsi);
          add_data_to_session(pss->session, isBinary, (const char *)in, len);
        }
        break;

    default:
        break;
    }

    return 0;
}
