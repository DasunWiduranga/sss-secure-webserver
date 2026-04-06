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

// =============================================================================
// Section 3: HTTP Request/Response Structures
// =============================================================================
 
/**
 * @struct HttpRequest
 * @brief Parsed representation of an incoming HTTP request.
 *
 * Security note: All fields are populated by the parser after input
 * validation. The parser enforces maximum sizes on each field to
 * prevent buffer exhaustion attacks.
 */
struct HttpRequest {
    std::string method;                              ///< HTTP method (GET, POST, etc.)
    std::string path;                                ///< Request URI path (validated)
    std::string version;                             ///< HTTP version string
    std::map<std::string, std::string> headers;      ///< Parsed request headers
    std::string body;                                ///< Request body (for POST)
    std::map<std::string, std::string> query_params;  ///< Parsed query string parameters
    std::map<std::string, std::string> form_data;     ///< Parsed form POST data
};
 
/**
 * @struct HttpResponse
 * @brief Represents an HTTP response to be sent to the client.
 */
struct HttpResponse {
    int status_code = 200;                           ///< HTTP status code
    std::string status_text = "OK";                  ///< Status reason phrase
    std::map<std::string, std::string> headers;      ///< Response headers
    std::string body;                                ///< Response body content
 
    /**
     * @brief Serialise the response to a raw HTTP response string.
     * @return The complete HTTP response ready for transmission.
     *
     * Security: Always includes security-relevant headers such as
     * Content-Length (to prevent response splitting) and
     * X-Content-Type-Options (to prevent MIME-sniffing).
     */
    std::string serialize() const {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
        for (const auto& [key, value] : headers) {
            oss << key << ": " << value << "\r\n";
        }
        oss << "Content-Length: " << body.size() << "\r\n";
        oss << "\r\n";
        oss << body;
        return oss.str();
    }
};

// =============================================================================
// Section 4: Input Validation and Sanitisation
// =============================================================================
 
/**
 * @class InputValidator
 * @brief Static utility class for validating and sanitising all untrusted input.
 *
 * Security rationale: All data received from the TCP socket is untrusted.
 * This class centralises validation logic, applying the CSSLP principle of
 * "Complete Mediation" — every access to a resource must be validated.
 *
 * Key defences:
 *  - Path traversal prevention (CWE-22)
 *  - Request size limiting (CWE-400)
 *  - Header injection prevention (CWE-113)
 *  - Null byte injection prevention (CWE-158)
 */
class InputValidator {
public:
    /// Maximum allowed size for an HTTP request (headers + body) in bytes
    static constexpr size_t MAX_REQUEST_SIZE = 1 * 1024 * 1024;  // 1 MB
 
    /// Maximum allowed length for a URI path
    static constexpr size_t MAX_URI_LENGTH = 2048;
 
    /// Maximum allowed size for a single HTTP header value
    static constexpr size_t MAX_HEADER_SIZE = 8192;
 
    /// Maximum number of headers per request
    static constexpr size_t MAX_HEADER_COUNT = 100;
 
    /// Maximum POST body size
    static constexpr size_t MAX_BODY_SIZE = 512 * 1024;  // 512 KB
 
    /**
     * @brief Validate and sanitise a URI path against path traversal attacks.
     * @param path The raw URI path from the HTTP request.
     * @param webroot The server's document root directory.
     * @return The resolved canonical filesystem path, or empty string if invalid.
     *
     * Defence against CWE-22 (Path Traversal):
     *  1. Reject paths containing null bytes
     *  2. URL-decode the path
     *  3. Reject encoded traversal sequences (double-encoding attacks)
     *  4. Resolve to canonical (absolute) path using std::filesystem
     *  5. Verify the canonical path starts with the webroot
     *
     * This implements the OWASP recommendation of canonicalisation followed
     * by prefix checking, which is more robust than blacklist filtering.
     */
    static std::string sanitizePath(const std::string& path,
                                     const std::string& webroot) {
        // Reject null bytes — prevents CWE-158 null byte injection
        if (path.find('\0') != std::string::npos) {
            LOG_WARNING("Null byte detected in request path — rejected");
            return "";
        }
 
        // Reject excessively long URIs
        if (path.length() > MAX_URI_LENGTH) {
            LOG_WARNING("URI exceeds maximum length — rejected");
            return "";
        }
 
        // URL-decode the path
        std::string decoded = urlDecode(path);
 
        // After decoding, check again for traversal patterns
        // This catches double-encoding attacks (%252e%252e%252f)
        if (decoded.find("..") != std::string::npos) {
            LOG_WARNING("Path traversal sequence detected after decoding: " + decoded);
            return "";
        }
 
        // Build the candidate path relative to webroot
        // Default "/" to "/index.html"
        std::string relative = (decoded == "/") ? "/index.html" : decoded;
 
        // Remove leading slash for path concatenation
        if (!relative.empty() && relative[0] == '/') {
            relative = relative.substr(1);
        }
 
        try {
            // Canonicalise using std::filesystem
            fs::path candidate = fs::canonical(fs::path(webroot) / relative);
            fs::path root = fs::canonical(fs::path(webroot));
 
            // Verify the resolved path is within the webroot
            // This is the critical check that prevents path traversal
            std::string cand_str = candidate.string();
            std::string root_str = root.string();
            if (cand_str.substr(0, root_str.size()) != root_str) {
                LOG_WARNING("Path traversal attempt blocked: " + path +
                            " resolved to " + cand_str);
                return "";
            }
 
            return cand_str;
        } catch (const fs::filesystem_error& e) {
            // File does not exist or permission denied
            LOG_DEBUG("Path resolution failed for '" + path + "': " + e.what());
            return "";
        }
    }
 
    /**
     * @brief URL-decode a percent-encoded string.
     * @param str The URL-encoded input string.
     * @return The decoded string.
     */
    static std::string urlDecode(const std::string& str) {
        std::string result;
        result.reserve(str.size());
        for (size_t i = 0; i < str.size(); ++i) {
            if (str[i] == '%' && i + 2 < str.size()) {
                std::string hex = str.substr(i + 1, 2);
                try {
                    char c = static_cast<char>(std::stoi(hex, nullptr, 16));
                    result += c;
                    i += 2;
                } catch (...) {
                    result += str[i];  // Invalid encoding — keep literal '%'
                }
            } else if (str[i] == '+') {
                result += ' ';  // Form encoding: '+' represents space
            } else {
                result += str[i];
            }
        }
        return result;
    }
 
    /**
     * @brief Parse URL-encoded form data (application/x-www-form-urlencoded).
     * @param body The raw form body.
     * @return Map of key-value pairs, URL-decoded.
     */
    static std::map<std::string, std::string> parseFormData(const std::string& body) {
        std::map<std::string, std::string> params;
        std::istringstream stream(body);
        std::string pair;
        while (std::getline(stream, pair, '&')) {
            auto pos = pair.find('=');
            if (pos != std::string::npos) {
                std::string key = urlDecode(pair.substr(0, pos));
                std::string value = urlDecode(pair.substr(pos + 1));
                // Sanitise: truncate excessively long values
                if (value.size() > MAX_HEADER_SIZE) {
                    value = value.substr(0, MAX_HEADER_SIZE);
                    LOG_WARNING("Truncated oversized form value for key: " + key);
                }
                params[key] = value;
            }
        }
        return params;
    }
 
    /**
     * @brief Parse query string parameters from a URI.
     * @param query The query string (after '?').
     * @return Map of decoded key-value pairs.
     */
    static std::map<std::string, std::string> parseQueryString(const std::string& query) {
        return parseFormData(query);  // Same encoding format
    }
 
    /**
     * @brief Validate an HTTP method string.
     * @param method The method extracted from the request line.
     * @return true if the method is supported and well-formed.
     *
     * Security: Only allows explicitly supported methods. Unknown
     * methods are rejected (fail-safe default / deny-by-default).
     */
    static bool isValidMethod(const std::string& method) {
        return method == "GET" || method == "POST" ||
               method == "HEAD" || method == "OPTIONS";
    }
};

// =============================================================================
// Section 6: MIME Type Detection
// =============================================================================
 
/**
 * @class MimeTypes
 * @brief Maps file extensions to MIME type strings.
 *
 * Security note: Correct MIME typing prevents browsers from
 * misinterpreting content. Combined with X-Content-Type-Options: nosniff,
 * this mitigates content-type sniffing attacks (CWE-16).
 */
class MimeTypes {
public:
    /**
     * @brief Determine the MIME type for a file based on its extension.
     * @param path The filesystem path to the file.
     * @return The MIME type string; defaults to "application/octet-stream".
     */
    static std::string getType(const std::string& path) {
        static const std::map<std::string, std::string> types = {
            {".html", "text/html"},
            {".htm",  "text/html"},
            {".css",  "text/css"},
            {".js",   "application/javascript"},
            {".json", "application/json"},
            {".png",  "image/png"},
            {".jpg",  "image/jpeg"},
            {".jpeg", "image/jpeg"},
            {".gif",  "image/gif"},
            {".svg",  "image/svg+xml"},
            {".ico",  "image/x-icon"},
            {".txt",  "text/plain"},
            {".pdf",  "application/pdf"},
            {".xml",  "application/xml"},
            {".woff", "font/woff"},
            {".woff2","font/woff2"},
        };
 
        fs::path p(path);
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
 
        auto it = types.find(ext);
        if (it != types.end()) {
            return it->second;
        }
        // Default: binary stream — safest default (prevents execution)
        return "application/octet-stream";
    }
};

// =============================================================================
// Section 8: Request Router and Response Builder
// =============================================================================
 
/**
 * @class RequestHandler
 * @brief Routes HTTP requests and constructs appropriate responses.
 *
 * Security design:
 *  - All file serving goes through InputValidator::sanitizePath()
 *  - Security headers are added to every response (defence in depth)
 *  - Error responses reveal minimal information (fail-safe defaults)
 *  - POST form handling is delegated to the sandboxed FormHandler
 */
class RequestHandler {
public:
    /**
     * @brief Construct a RequestHandler with the specified webroot.
     * @param webroot The document root directory for serving files.
     */
    explicit RequestHandler(const std::string& webroot)
        : webroot_(webroot),
          submissions_dir_(webroot + "/../submissions") {}
 
    /**
     * @brief Process an HTTP request and produce a response.
     * @param request The parsed HTTP request.
     * @return An HttpResponse ready for serialisation.
     */
    HttpResponse handleRequest(const HttpRequest& request) {
        HttpResponse response;
        addSecurityHeaders(response);
 
        if (request.method.empty()) {
            return buildErrorResponse(400, "Bad Request");
        }
 
        // Route based on HTTP method
        if (request.method == "GET" || request.method == "HEAD") {
            return handleGet(request);
        } else if (request.method == "POST") {
            return handlePost(request);
        } else if (request.method == "OPTIONS") {
            response.status_code = 200;
            response.status_text = "OK";
            response.headers["Allow"] = "GET, POST, HEAD, OPTIONS";
            addSecurityHeaders(response);
            return response;
        }
 
        return buildErrorResponse(405, "Method Not Allowed");
    }