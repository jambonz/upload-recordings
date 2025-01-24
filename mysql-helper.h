#ifndef MYSQL_HELPER_H
#define MYSQL_HELPER_H

#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>
#include <memory>
#include <unordered_map>

// Struct for user credentials
struct RecordCredentials {
    std::string recordFormat;
    std::string bucketCredential;
};

class MySQLHelper {
public:
    // Singleton accessor
    static MySQLHelper& getInstance(size_t poolSize = 10);

    // Destructor
    ~MySQLHelper();

    // Acquire and release connections
    std::shared_ptr<sql::Connection> getConnection();
    void releaseConnection(std::shared_ptr<sql::Connection> connection);

    RecordCredentials fetchRecordCredentials(std::string& accountSid);

private:
    // Private constructor for singleton pattern
    MySQLHelper(size_t poolSize);

    // Helper methods
    void initializePool();

    size_t poolSize_;
    sql::Driver* driver_;
    std::queue<std::shared_ptr<sql::Connection>> connectionPool_;
    std::mutex poolMutex_;
    std::condition_variable poolCv_;

    // MySQL connection details
    std::string host_;
    std::string user_;
    std::string password_;
    std::string database_;
};

#endif // MYSQL_HELPER_H