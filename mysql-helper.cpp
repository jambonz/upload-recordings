#include "mysql-helper.h"
#include <stdexcept>
#include <cstdlib>
#include <memory>
#include <iostream>
#include <thread>
#include <chrono>

namespace {
    // Returns the first of the two variables that is set and non-empty.
    const char* envOr(const char* preferred, const char* fallback) {
        const char* v = std::getenv(preferred);
        if (v && *v) return v;
        v = std::getenv(fallback);
        return (v && *v) ? v : nullptr;
    }
}

MySQLHelper::MySQLHelper(size_t poolSize) : poolSize_(poolSize) {
    const char* hostEnv = std::getenv("MYSQL_HOST");
    const char* userEnv = std::getenv("MYSQL_USER");

    // Prefer JAMBONES_MYSQL_PASSWORD, falling back to MYSQL_PASSWORD.
    //
    // Every other jambonz component reads JAMBONES_MYSQL_PASSWORD; this one has
    // always read the unprefixed name. That difference does not matter when a
    // deploy script sets both, but it does when the credential comes from a
    // shared secret store: a parameter is mapped to an environment variable by
    // name, so a single JAMBONES_MYSQL_PASSWORD entry would reach this process
    // under a name it never looks at, and it would silently keep using whatever
    // was baked into the unit file.
    //
    // The fallback keeps existing deployments working unchanged.
    //
    // Deliberately NOT applied to MYSQL_HOST: that value is per-role. The web
    // tier points JAMBONES_MYSQL_HOST at the Aurora writer because it
    // initialises the schema, while this service only ever reads and belongs on
    // the reader. Preferring the prefixed name here would couple this service's
    // endpoint choice to whatever the node apps on the same host were given.
    const char* passwordEnv = envOr("JAMBONES_MYSQL_PASSWORD", "MYSQL_PASSWORD");
    const char* databaseEnv = std::getenv("MYSQL_DATABASE");

    if (!hostEnv || !userEnv || !passwordEnv || !databaseEnv) {
        throw std::runtime_error(
            "Missing one or more required environment variables: MYSQL_HOST, MYSQL_USER, "
            "JAMBONES_MYSQL_PASSWORD (or MYSQL_PASSWORD), MYSQL_DATABASE"
        );
    }

    host_ = hostEnv;
    user_ = userEnv;
    password_ = passwordEnv;
    database_ = databaseEnv;

    driver_ = get_driver_instance();
    initializePool();
}

MySQLHelper::~MySQLHelper() {
    while (!connectionPool_.empty()) {
        connectionPool_.pop();
    }
}

void MySQLHelper::initializePool() {
    for (size_t i = 0; i < poolSize_; ++i) {
        auto conn = std::shared_ptr<sql::Connection>(
            driver_->connect(host_, user_, password_),
            [](sql::Connection* connection) { delete connection; }
        );
        conn->setSchema(database_);
        connectionPool_.push(conn);
    }

    // Start a thread to keep connections alive
    std::thread([this]() {
        while (true) {
            // Run every 5 minutes
            std::this_thread::sleep_for(std::chrono::minutes(5));
            for (size_t i = 0; i < poolSize_; ++i) {
                auto connection = getConnection();
                try {
                    auto stmt = std::unique_ptr<sql::PreparedStatement>(connection->prepareStatement("SELECT 1"));
                    auto res = std::unique_ptr<sql::ResultSet>(stmt->executeQuery());
                    // comsume the result
                    res->next();
                } catch (const sql::SQLException& e) {
                    std::cerr << "MySQL error during keep-alive: " << e.what() << std::endl;
                    // Attempt to reconnect
                    try {
                        connection.reset(driver_->connect(host_, user_, password_));
                        connection->setSchema(database_);
                        std::cerr << "Reconnected to MySQL server." << std::endl;
                    } catch (const sql::SQLException& reconnectException) {
                        std::cerr << "MySQL reconnection failed: " << reconnectException.what() << std::endl;
                    }
                }
                releaseConnection(connection);
            }
        }
    }).detach();
}

std::shared_ptr<sql::Connection> MySQLHelper::getConnection() {
    std::unique_lock<std::mutex> lock(poolMutex_);
    poolCv_.wait(lock, [this]() { return !connectionPool_.empty(); });

    auto conn = connectionPool_.front();
    connectionPool_.pop();
    return conn;
}

void MySQLHelper::releaseConnection(std::shared_ptr<sql::Connection> connection) {
    std::lock_guard<std::mutex> lock(poolMutex_);
    connectionPool_.push(connection);
    poolCv_.notify_one();
}

RecordCredentials MySQLHelper::fetchRecordCredentials(std::string& accountSid) {
    auto connection = getConnection();
    RecordCredentials credentials;

    try {
        auto stmt = std::unique_ptr<sql::PreparedStatement>(
          connection->prepareStatement(
            "SELECT record_format, bucket_credential, eval_credential FROM accounts WHERE account_sid = ?")
        );
        stmt->setString(1, accountSid);

        auto res = std::unique_ptr<sql::ResultSet>(stmt->executeQuery());
        if (res->next()) {
            credentials.recordFormat = res->getString("record_format");
            credentials.bucketCredential = res->getString("bucket_credential");
            credentials.evalCredential = res->getString("eval_credential");
        } else {
            releaseConnection(connection);
            throw std::runtime_error("Account not found for SID: " + accountSid);
        }
    } catch (const sql::SQLException& e) {
        std::cerr << "MySQL error while fetching record credentials: " << e.what() << std::endl;
        releaseConnection(connection);
        throw;
    }

    releaseConnection(connection);
    return credentials;
}

bool MySQLHelper::verifyConnectivity(size_t poolSize) {
    // getInstance() holds a function-local static, so the pool - and therefore
    // the first connection attempt - is created lazily on first use. The only
    // caller is the recording session handler, which meant a wrong password or
    // an unreachable host was not discovered until someone placed a call.
    // Calling this at startup surfaces it in the service log instead.
    //
    // Deliberately non-fatal: if the constructor throws, the static is not
    // marked initialised and C++ retries construction on the next getInstance(),
    // so a database that is briefly unavailable at boot still recovers on its
    // own without the service restart-looping.
    try {
        auto& helper = getInstance(poolSize);
        auto conn = helper.getConnection();
        auto stmt = std::unique_ptr<sql::PreparedStatement>(conn->prepareStatement("SELECT 1"));
        auto res = std::unique_ptr<sql::ResultSet>(stmt->executeQuery());
        res->next();
        helper.releaseConnection(conn);
        return true;
    } catch (const sql::SQLException& e) {
        std::cerr << "FATAL: cannot connect to MySQL: " << e.what() << std::endl;
        std::cerr << "       recordings will fail until this is resolved. Check MYSQL_HOST, MYSQL_USER, "
                  << "JAMBONES_MYSQL_PASSWORD (or MYSQL_PASSWORD) and MYSQL_DATABASE." << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "FATAL: cannot initialise MySQL connection pool: " << e.what() << std::endl;
        std::cerr << "       recordings will fail until this is resolved." << std::endl;
        return false;
    }
}

MySQLHelper& MySQLHelper::getInstance(size_t poolSize) {
    static MySQLHelper instance(poolSize);
    return instance;
}