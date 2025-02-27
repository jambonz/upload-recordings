// thread-pool.h
#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <boost/asio.hpp>
#include <vector>
#include <thread>
#include <memory>
#include <atomic>
#include <spdlog/spdlog.h>
#include "string-utils.h"

class ThreadPool {
public:
    // Singleton pattern for global thread pool access
    static ThreadPool& getInstance() {
        static ThreadPool instance;
        return instance;
    }

    // Get the io_context to post tasks
    boost::asio::io_context& getIoContext() {
        return io_context_;
    }

    // Post a task to the thread pool
    template<typename Task>
    void post(Task&& task) {
        boost::asio::post(io_context_, std::forward<Task>(task));
    }

    // Create a strand for serialized execution
    boost::asio::io_context::strand createStrand() {
        return boost::asio::io_context::strand(io_context_);
    }

    // Get number of worker threads
    size_t threadCount() const {
        return threads_.size();
    }

    // Get current queued task count (approximate)
    size_t queuedTaskCount() const {
        return tasks_queued_.load();
    }

    // Get current active task count (approximate)
    size_t activeTaskCount() const {
        return tasks_active_.load();
    }

    // Shutdown the thread pool
    void shutdown() {
        spdlog::info("Shutting down thread pool with {} threads", threads_.size());
        work_guard_.reset();
        for (auto& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        spdlog::info("Thread pool shutdown complete");
    }

private:
    // Private constructor (singleton)
    ThreadPool(int num_threads = std::thread::hardware_concurrency())
        : io_context_(),
          work_guard_(boost::asio::make_work_guard(io_context_)),
          tasks_queued_(0),
          tasks_active_(0) {
        
        spdlog::info("Creating thread pool with {} threads", num_threads);
        
        // Create worker threads
        for (int i = 0; i < num_threads; ++i) {
            threads_.emplace_back([this, i]() {
                try {
                  std::string threadId = getThreadIdString();
              
                    spdlog::info("Thread pool worker {} started, thread id: {}", i, threadId);
                    io_context_.run();
                    spdlog::info("Thread pool worker {} exiting, thread id: {}", i, threadId);
                }
                catch (const std::exception& e) {
                    spdlog::error("Thread pool worker {} exception: {}", i, e.what());
                }
            });
        }
    }

    // Deleted copy/move constructors and assignment operators
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    ~ThreadPool() {
        shutdown();
    }

    boost::asio::io_context io_context_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::vector<std::thread> threads_;
    std::atomic<size_t> tasks_queued_;
    std::atomic<size_t> tasks_active_;
};

#endif // THREAD_POOL_H