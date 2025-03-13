#include "mysql-helper.h"
#include <stdexcept>
#include <iostream>
#include <thread>
#include <chrono>

MySQLHelper::MySQLHelper(size_t poolSize) : poolSize_(poolSize) {
    const char* hostEnv = std::getenv("MYSQL_HOST");
    const char* userEnv = std::getenv("MYSQL_USER");
    const char* passwordEnv = std::getenv("MYSQL_PASSWORD");
    const char* databaseEnv = std::getenv("MYSQL_DATABASE");

    if (!hostEnv || !userEnv || !passwordEnv || !databaseEnv) {
        throw std::runtime_error(
            "Missing one or more required environment variables: MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE"
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
        // Ensure connection stays alive by setting a ping mechanism
        if (conn->isValid()) { 
            std::thread([conn]() {
                while (true) {
                    std::this_thread::sleep_for(std::chrono::minutes(1)); // Ping every 5 minutes
                    try {
                        if (!conn->isValid()) {
                            std::cerr << "MySQL connection is invalid, reconnecting...\n";
                            conn->reconnect();
                        } else {
                            conn->prepareStatement("SELECT 1")->execute(); // Keep connection alive
                        }
                    } catch (const sql::SQLException &e) {
                        std::cerr << "MySQL ping failed: " << e.what() << std::endl;
                    }
                }
            }).detach();
        }
        connectionPool_.push(conn);
    }
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
          connection->prepareStatement("SELECT record_format, bucket_credential FROM accounts WHERE account_sid = ?")
        );
        stmt->setString(1, accountSid);

        auto res = std::unique_ptr<sql::ResultSet>(stmt->executeQuery());
        if (res->next()) {
            credentials.recordFormat = res->getString("record_format");
            credentials.bucketCredential = res->getString("bucket_credential");

            //std::cout << "Record format: " << credentials.recordFormat << ", Bucket credential: " << credentials.bucketCredential << std::endl;
        } else {
            throw std::runtime_error("Account not found for SID: " + accountSid);
        }
    } catch (const sql::SQLException& e) {
        std::cerr << "MySQL error while fetching record credentials: " << e.what() << std::endl;
        throw;
    }

    releaseConnection(connection);
    return credentials;
}

MySQLHelper& MySQLHelper::getInstance(size_t poolSize) {
    static MySQLHelper instance(poolSize);
    return instance;
}