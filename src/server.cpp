#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#include <cerrno>

// POSIX / Linux headers
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

// Linux sandboxing
#include <seccomp.h>
#include <sys/prctl.h>

namespace fs = std::filesystem;

// =============================================================================
// Section 1: Logging Subsystem
// =============================================================================

/**
 * @enum LogLevel
 * @brief Severity levels for the logging subsystem.
 *
 * Security rationale: Structured logging supports the CSSLP principle of
 * Accountability and Auditing (Domain 1). All security-relevant events
 * are logged at appropriate severity levels to facilitate incident
 * investigation and compliance auditing.
 */
enum class LogLevel {
    DEBUG   = 0,  ///< Verbose debug information (development only)
    INFO    = 1,  ///< Normal operational messages
    WARNING = 2,  ///< Potentially harmful situations
    ERROR   = 3,  ///< Error events that might still allow continued operation
    FATAL   = 4   ///< Severe errors that will cause the server to abort
};

/**
 * @class Logger
 * @brief Thread-safe singleton logger with severity filtering.
 *
 * Security design: The logger uses a mutex to ensure thread safety,
 * preventing interleaved log messages that could obscure security events.
 * Log output goes to both stderr and a log file for persistence.
 *
 * Principle: US-CERT BSI - "Logging and Auditing" — all actions that
 * affect security state must be recorded.
 */
class Logger {
public:
    /**
     * @brief Get the singleton Logger instance.
     * @return Reference to the global Logger.
     *
     * Uses Meyer's Singleton pattern — thread-safe in C++11 and later
     * without requiring explicit synchronisation for initialisation.
     */
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    /**
     * @brief Set the minimum log level for output filtering.
     * @param level Minimum severity to display.
     */
    void setLevel(LogLevel level) {
        min_level_ = level;
    }

    /**
     * @brief Set the log file path and open it for appending.
     * @param path Filesystem path for the persistent log file.
     */
    void setLogFile(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (log_file_.is_open()) {
            log_file_.close();
        }
        log_file_.open(path, std::ios::app);
        if (!log_file_.is_open()) {
            std::cerr << "[LOGGER] Failed to open log file: " << path << std::endl;
        }
    }

    /**
     * @brief Write a log entry at the specified severity level.
     * @param level The severity of the message.
     * @param message The log message content.
     *
     * Format: [YYYY-MM-DD HH:MM:SS] [LEVEL] message
     * Messages below the configured minimum level are silently discarded.
     */
    void log(LogLevel level, const std::string& message) {
        if (level < min_level_) return;

        std::lock_guard<std::mutex> lock(mutex_);
        std::string timestamp = getTimestamp();
        std::string level_str = levelToString(level);
        std::string entry = "[" + timestamp + "] [" + level_str + "] " + message;

        std::cerr << entry << std::endl;
        if (log_file_.is_open()) {
            log_file_ << entry << std::endl;
            log_file_.flush();  // Ensure immediate write for crash recovery
        }
    }

    // Delete copy/move to enforce singleton
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    Logger() : min_level_(LogLevel::INFO) {}

    /**
     * @brief Generate an ISO 8601 timestamp string.
     * @return Formatted timestamp for log entries.
     */
    std::string getTimestamp() const {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
        localtime_r(&time, &tm_buf);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
        return std::string(buf);
    }

    /**
     * @brief Convert a LogLevel enum value to its string representation.
     */
    std::string levelToString(LogLevel level) const {
        switch (level) {
            case LogLevel::DEBUG:   return "DEBUG";
            case LogLevel::INFO:    return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR:   return "ERROR";
            case LogLevel::FATAL:   return "FATAL";
            default:                return "UNKNOWN";
        }
    }

    std::mutex mutex_;              ///< Guards all log output operations
    std::ofstream log_file_;        ///< Persistent log file stream
    LogLevel min_level_;            ///< Minimum severity for output
};

/// Convenience macros for logging at each severity level
#define LOG_DEBUG(msg)   Logger::instance().log(LogLevel::DEBUG, msg)
#define LOG_INFO(msg)    Logger::instance().log(LogLevel::INFO, msg)
#define LOG_WARNING(msg) Logger::instance().log(LogLevel::WARNING, msg)
#define LOG_ERROR(msg)   Logger::instance().log(LogLevel::ERROR, msg)
#define LOG_FATAL(msg)   Logger::instance().log(LogLevel::FATAL, msg)