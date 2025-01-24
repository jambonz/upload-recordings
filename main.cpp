#include <libwebsockets.h>
#include <cstring>
#include <csignal>
#include <iostream>
#include <string>
#include <cstdlib>
#include <atomic>
#include <aws/core/Aws.h>

extern const struct lws_protocols protocols[]; // Declare protocols here

static const lws_retry_bo_t retry = {
    .secs_since_valid_ping = 3,
    .secs_since_valid_hangup = 10,
};

static std::atomic<bool> interrupted(false); // Fix for atomic declaration

#if defined(LWS_WITH_PLUGINS)
/* if plugins enabled, only protocols explicitly named in pvo bind to vhost */
static lws_protocol_vhost_options pvo = { nullptr, nullptr, "lws-minimal", "" };
#endif

void sigint_handler(int sig) {
    interrupted = true; // Use the corrected atomic variable
}

// Parse command-line arguments
int parse_port(int argc, const char **argv, int default_port) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            return std::atoi(argv[i + 1]);
        }
    }
    return default_port;
}

int main(int argc, const char **argv) {
    lws_context_creation_info info;
    lws_context *context;
    const char *p;
    int n = 0;

    Aws::SDKOptions options;
    try {
      options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Debug;
      Aws::InitAPI(options);

      int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
      int port = parse_port(argc, argv, 3017); // Default to 3017 if --port is not provided

      // Set the SIGINT handler
      std::signal(SIGINT, sigint_handler);

      // Check for log level argument
      if ((p = lws_cmdline_option(argc, argv, "-d"))) {
          logs = std::atoi(p);
      }

      lws_set_log_level(logs, nullptr);
      std::cout << "jambonz recording server (ws) | Listening on http://localhost:" << port
                << " (-s = use TLS / https)\n";

      // Initialize info struct
      std::memset(&info, 0, sizeof(info));
      info.port = port;
      info.protocols = protocols;

  #if defined(LWS_WITH_PLUGINS)
      info.pvo = &pvo;
  #endif
      info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

  #if defined(LWS_WITH_TLS)
      if (lws_cmdline_option(argc, argv, "-s")) {
          std::cout << "Server using TLS\n";
          info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
          info.ssl_cert_filepath = "localhost-100y.cert";
          info.ssl_private_key_filepath = "localhost-100y.key";
      }
  #endif

      if (lws_cmdline_option(argc, argv, "-h")) {
          info.options |= LWS_SERVER_OPTION_VHOST_UPG_STRICT_HOST_CHECK;
      }

      if (lws_cmdline_option(argc, argv, "-v")) {
          info.retry_and_idle_policy = &retry;
      }

      context = lws_create_context(&info);
      if (!context) {
          lwsl_err("lws init failed\n");
          return 1;
      }

      while (n >= 0 && !interrupted) { // Use the corrected atomic variable
          n = lws_service(context, 0);
      }

      std::cerr << "lws thread Exiting...\n";
      lws_context_destroy(context);
      std::cerr << "lws context destroyed...\n";

    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    // Shutdown AWS SDK
    std::cerr << "Shutting down AWS SDK" << std::endl;
    Aws::ShutdownAPI(options);
    std::cerr << "AWS SDK shutdown complete" << std::endl;


    return 0;
}
