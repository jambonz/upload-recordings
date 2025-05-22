#include <libwebsockets.h>
#include <cstring>
#include <csignal>
#include <iostream>
#include <string>
#include <cstdlib>
#include <atomic>

#include <aws/core/Aws.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <memory>

#include "thread-pool.h"
#include "connection-manager.h"
#include "string-utils.h"

extern const struct lws_protocols protocols[];

static const lws_retry_bo_t retry = {
    .secs_since_valid_ping = 3,
    .secs_since_valid_hangup = 10,
};

static std::atomic<bool> interrupted(false);

#if defined(LWS_WITH_PLUGINS)
/* if plugins enabled, only protocols explicitly named in pvo bind to vhost */
static lws_protocol_vhost_options pvo = { nullptr, nullptr, "lws-minimal", "" };
#endif

void sigint_handler(int sig) {
    interrupted = true;
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

// Parse thread count from command line
int parse_thread_count(int argc, const char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            return std::atoi(argv[i + 1]);
        }
    }
    return std::thread::hardware_concurrency(); // Default to hardware concurrency
}

// Parse AWS max connections from command line
int parse_aws_max_connections(int argc, const char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--aws-max-connections") == 0 && i + 1 < argc) {
            return std::atoi(argv[i + 1]);
        }
    }
    return std::thread::hardware_concurrency() * 2; // Default to CPU count * 2
}

// Parse buffer process size from command line (in KB)
size_t parse_buffer_process_size(int argc, const char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--buffer-process-size") == 0 && i + 1 < argc) {
            return std::atoi(argv[i + 1]) * 1024; // Convert KB to bytes
        }
    }
    return 512 * 1024; // Default 512KB
}

// Parse max buffer size from command line (in MB)
size_t parse_max_buffer_size(int argc, const char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--max-buffer-size") == 0 && i + 1 < argc) {
            return std::atoi(argv[i + 1]) * 1024 * 1024; // Convert MB to bytes
        }
    }
    return 3 * 1024 * 1024; // Default 3MB
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  --port PORT                   Server port (default: 3017)\n"
              << "  --threads COUNT               Thread pool size (default: CPU count)\n"
              << "  --aws-max-connections COUNT   AWS S3 max connections (default: CPU count * 2)\n"
              << "  --buffer-process-size KB      Buffer processing threshold in KB (default: 512)\n"
              << "  --max-buffer-size MB          Maximum buffer size per session in MB (default: 3)\n"
              << "  -v, --version                 Show version\n"
              << "  -h, --help                    Show this help\n"
              << "  -d LOG_LEVEL                  LWS debug log level\n"
              << "  -s                            Enable TLS\n"
              << "\nEnvironment Variables:\n"
              << "  LOG_LEVEL                     Application log level (debug, info, warn, error)\n"
              << "  ENCRYPTION_SECRET             Required for credential decryption\n"
              << "  JAMBONZ_UPLOADER_TMP_FOLDER   Temporary upload folder (default: /tmp/uploads)\n"
              << "  BASIC_AUTH_USERNAME           WebSocket basic auth username\n"
              << "  BASIC_AUTH_PASSWORD           WebSocket basic auth password\n";
}

int main(int argc, const char **argv) {
    lws_context_creation_info info;
    lws_context *context;
    const char *p;
    int n = 0;

    // Check for help flag first
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Create a non-colored stdout sink
    auto stdout_sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();

    // Create the logger using the non-colored sink
    auto logger = std::make_shared<spdlog::logger>("uploader", stdout_sink);

    // Set it as the default logger
    spdlog::set_default_logger(logger);

    // Check for version flag first, before any other logging
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-v") == 0 || std::strcmp(argv[i], "--version") == 0) {
            std::cout << "jambonz recording server (ws) version " << UPLOADER_VERSION << std::endl;
            return 0;
        }
    }

    // Check for required environment variables only if we're actually starting the server
    const char* encryption_secret = std::getenv("ENCRYPTION_SECRET");
    if (!encryption_secret) {
        throw std::runtime_error("ENCRYPTION_SECRET environment variable is not set");
    }

    std::string threadId = getThreadIdString();
    spdlog::info("Main thread id: {}", threadId);

    // Set the log level from an environment variable
    const char* env_log_level = std::getenv("LOG_LEVEL");
    spdlog::level::level_enum level = spdlog::level::info; // Default level: info
    if (env_log_level) {
        std::string level_str(env_log_level);
        if (level_str == "debug") {
            std::cout << "Setting log level to debug" << std::endl;
            level = spdlog::level::debug;
        }
        else if (level_str == "info") level = spdlog::level::info;
        else if (level_str == "warn") level = spdlog::level::warn;
        else if (level_str == "error") level = spdlog::level::err;
    }
    spdlog::set_level(level);
    
    // Parse configuration from command line
    int thread_count = parse_thread_count(argc, argv);
    int aws_max_connections = parse_aws_max_connections(argc, argv);
    size_t buffer_process_size = parse_buffer_process_size(argc, argv);
    size_t max_buffer_size = parse_max_buffer_size(argc, argv);
    int port = parse_port(argc, argv, 3017);
    
    spdlog::info("Configuration:");
    spdlog::info("  Thread pool size: {}", thread_count);
    spdlog::info("  AWS max connections: {}", aws_max_connections);
    spdlog::info("  Buffer process size: {} KB", buffer_process_size / 1024);
    spdlog::info("  Max buffer size: {} MB", max_buffer_size / (1024 * 1024));
    spdlog::info("  Server port: {}", port);
    
    Aws::SDKOptions options;
    try {
        options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Debug;
        Aws::InitAPI(options);

        // Initialize the thread pool with parsed thread count
        auto& threadPool = ThreadPool::getInstance(thread_count);
        
        // Initialize the connection manager
        auto& connectionManager = ConnectionManager::getInstance();
        
        // Set global configuration values for Session class
        Session::setGlobalConfig(buffer_process_size, max_buffer_size, aws_max_connections);

        int logs = LLL_ERR | LLL_WARN;

        // Set the SIGINT handler
        std::signal(SIGINT, sigint_handler);
        std::signal(SIGTERM, sigint_handler);

        // Check for log level argument
        if ((p = lws_cmdline_option(argc, argv, "-d"))) {
            logs = std::atoi(p);
        }

        lws_set_log_level(logs, nullptr);
        spdlog::info("jambonz recording server (ws) version {} | Listening on http://localhost:{}", 
            UPLOADER_VERSION, port);
        
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
            spdlog::info("Server using TLS");
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

        while (n >= 0 && !interrupted) {
            n = lws_service(context, 5);
        }

        spdlog::info("Shutting down server...");
        lws_context_destroy(context);
        spdlog::info("LWS context destroyed");
                
        // Shutdown thread pool
        threadPool.shutdown();
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    
    // Shutdown AWS SDK
    spdlog::info("Shutting down AWS SDK");
    Aws::ShutdownAPI(options);
    spdlog::info("AWS SDK shutdown complete");

    return 0;
}
