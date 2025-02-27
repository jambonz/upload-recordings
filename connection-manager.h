#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <iostream>
#include <sstream>
#include <thread>
#include <spdlog/spdlog.h>
#include "session.h"

class ConnectionManager {
public:
    // Singleton pattern
    static ConnectionManager& getInstance() {
        static ConnectionManager instance;
        return instance;
    }

    // Create a new session for a connection
    void* createSession() {
        try {
            auto session = std::make_shared<Session>();
            void* rawPtr = session.get();
            
            {
                std::lock_guard<std::mutex> lock(mutex_);
                sessions_[rawPtr] = session;
                // Log the session count after creation
                spdlog::info("session created - there are now {} active sessions", sessions_.size());
            }
            
            return rawPtr;
        } catch (const std::exception& e) {
            spdlog::error("Failed to create session: {}", e.what());
            return nullptr;
        }
    }

    // Destroy a session with proper completion handling
    void destroySession(void* sessionPtr) {
        if (sessionPtr == nullptr) return;
        
        std::shared_ptr<Session> session;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = sessions_.find(sessionPtr);
            if (it == sessions_.end()) {
                spdlog::warn("destroySession: Session not found for destruction!");
                return;  // Session not found
            }

            session = it->second;
            
            sessions_.erase(it);
            session->log("session destroyed - there are now {} active sessions", sessions_.size()); 
        }
    }

    // Get session count
    size_t getSessionCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.size();
    }

private:
    ConnectionManager() = default;
    ~ConnectionManager() = default;
    
    // Deleted copy/move constructors and assignment operators
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    ConnectionManager(ConnectionManager&&) = delete;
    ConnectionManager& operator=(ConnectionManager&&) = delete;

    std::unordered_map<void*, std::shared_ptr<Session>> sessions_;
    mutable std::mutex mutex_;
};

#endif // CONNECTION_MANAGER_H