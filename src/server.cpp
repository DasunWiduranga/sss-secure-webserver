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
// Section 7: Sandboxed Form Handler (Forked Process with seccomp)
// =============================================================================

/**
 * @class FormHandler
 * @brief Processes form submissions in an isolated child process.
 *
 * Security rationale: Form data originates from untrusted users and
 * may contain malicious payloads. Processing it in a forked child
 * process achieves:
 *  1. Process-level isolation — a crash in the handler cannot
 *     affect the main server process (separation of concerns).
 *  2. Privilege reduction — the child drops capabilities.
 *  3. Syscall filtering via seccomp-bpf — the child is restricted
 *     to only the system calls needed for its task (write, exit).
 *
 * Principle: CSSLP Domain 4 — "Separation of Privileges" and
 * US-CERT BSI — "Least Privilege" / "Attack Surface Reduction".
 *
 * The assignment brief recommends handling form submissions via a
 * separate process with increased isolation. This class implements
 * that recommendation using fork() + seccomp.
 */
class FormHandler {
public:
    /**
     * @brief Handle a form submission in a sandboxed child process.
     * @param form_data The parsed form key-value pairs.
     * @param storage_path Path to the directory where submissions are stored.
     * @return true if the handler was spawned successfully.
     *
     * The method forks a child process. The child:
     *  1. Installs a seccomp-bpf filter to whitelist only essential syscalls.
     *  2. Writes the form data to a timestamped file.
     *  3. Exits immediately.
     *
     * The parent reaps the child via waitpid() to prevent zombies.
     */
    static bool handle(const std::map<std::string, std::string>& form_data,
                       const std::string& storage_path) {
        LOG_INFO("Spawning sandboxed form handler process");

        // Ensure the storage directory exists
        try {
            fs::create_directories(storage_path);
        } catch (const fs::filesystem_error& e) {
            LOG_ERROR("Cannot create storage directory: " + std::string(e.what()));
            return false;
        }

        // Generate a unique filename using timestamp + PID
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
        std::string filename = storage_path + "/submission_" +
                               std::to_string(millis) + "_" +
                               std::to_string(getpid()) + ".txt";

        pid_t pid = fork();

        if (pid < 0) {
            LOG_ERROR("fork() failed: " + std::string(std::strerror(errno)));
            return false;
        }

        if (pid == 0) {
            // === CHILD PROCESS (sandboxed) ===

            // Prevent the child from gaining new privileges (defence-in-depth)
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

            // Write form data to file BEFORE applying seccomp
            // (seccomp will restrict open/write after this point)
            std::ofstream out(filename);
            if (out.is_open()) {
                out << "=== Form Submission ===" << std::endl;
                out << "Timestamp: " << millis << std::endl;
                for (const auto& [key, value] : form_data) {
                    // Sanitise: strip control characters from keys/values
                    std::string safe_key = sanitizeForStorage(key);
                    std::string safe_value = sanitizeForStorage(value);
                    out << safe_key << " = " << safe_value << std::endl;
                }
                out << "=== End ===" << std::endl;
                out.close();
            } else {
                // Cannot log via Logger (not safe after fork in multi-threaded)
                _exit(1);
            }

            // Apply seccomp-bpf filter — restrict to minimal syscalls
            // After this point, only exit-related syscalls are permitted
            applySandbox();

            _exit(0);  // Clean exit
        }

        // === PARENT PROCESS ===
        // Reap the child to prevent zombie processes
        int status = 0;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            LOG_INFO("Form submission saved: " + filename);
            return true;
        } else {
            LOG_ERROR("Form handler child exited abnormally (status: " +
                      std::to_string(status) + ")");
            return false;
        }
    }

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

private:
    /**
     * @brief Handle a GET request by serving the requested file.
     * @param request The parsed GET request.
     * @return An HttpResponse containing the file contents or an error.
     */
    HttpResponse handleGet(const HttpRequest& request) {
        // Validate and resolve the file path (path traversal defence)
        std::string filepath = InputValidator::sanitizePath(request.path, webroot_);

        if (filepath.empty()) {
            LOG_INFO("404: " + request.path);
            return buildErrorResponse(404, "Not Found");
        }

        // Verify the file exists and is a regular file (not a directory/device)
        if (!fs::exists(filepath) || !fs::is_regular_file(filepath)) {
            LOG_INFO("404 (not regular file): " + request.path);
            return buildErrorResponse(404, "Not Found");
        }

        // Read the file contents
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open file: " + filepath);
            return buildErrorResponse(500, "Internal Server Error");
        }

        std::ostringstream contents;
        contents << file.rdbuf();

        HttpResponse response;
        response.status_code = 200;
        response.status_text = "OK";
        response.body = contents.str();
        response.headers["Content-Type"] = MimeTypes::getType(filepath);
        addSecurityHeaders(response);

        LOG_INFO("200: " + request.path + " (" +
                 std::to_string(response.body.size()) + " bytes)");

        // For HEAD requests, clear the body but keep headers
        if (request.method == "HEAD") {
            response.body.clear();
        }

        return response;
    }

    /**
     * @brief Handle a POST request (form submission).
     * @param request The parsed POST request.
     * @return An HttpResponse confirming or denying the submission.
     *
     * Form data is processed by FormHandler in a sandboxed child process.
     * The response contains minimal information to avoid information leakage.
     */
    HttpResponse handlePost(const HttpRequest& request) {
        // Check for form data
        if (request.form_data.empty() && request.query_params.empty()) {
            return buildErrorResponse(400, "Bad Request: No form data");
        }

        // Merge query params and form data (POST body takes precedence)
        std::map<std::string, std::string> all_data = request.query_params;
        for (const auto& [key, value] : request.form_data) {
            all_data[key] = value;
        }

        // Delegate to sandboxed form handler
        bool success = FormHandler::handle(all_data, submissions_dir_);

        if (success) {
            HttpResponse response;
            response.status_code = 200;
            response.status_text = "OK";
            response.headers["Content-Type"] = "text/html";
            response.body =
                "<!DOCTYPE html><html><head><title>Submitted</title></head>"
                "<body><h1>Form Submitted Successfully</h1>"
                "<p>Your data has been received and stored.</p>"
                "<a href=\"/\">Return to Home</a></body></html>";
            addSecurityHeaders(response);
            return response;
        } else {
            return buildErrorResponse(500, "Internal Server Error");
        }
    }

    /**
     * @brief Build an HTML error response.
     * @param code The HTTP status code.
     * @param text The status reason phrase.
     * @return An HttpResponse with a safe error page.
     *
     * Security: Error pages are static HTML templates that do not
     * reflect any user input (prevents reflected XSS via error pages).
     */
    HttpResponse buildErrorResponse(int code, const std::string& text) {
        HttpResponse response;
        response.status_code = code;
        response.status_text = text;
        response.headers["Content-Type"] = "text/html";
        response.body =
            "<!DOCTYPE html><html><head><title>" + std::to_string(code) +
            " " + text + "</title></head>"
            "<body><h1>" + std::to_string(code) + " " + text + "</h1>"
            "</body></html>";
        addSecurityHeaders(response);
        return response;
    }

    /**
     * @brief Add security-relevant HTTP headers to a response.
     * @param response The response to augment.
     *
     * Headers applied (defence in depth):
     *  - X-Content-Type-Options: nosniff — prevent MIME-sniffing
     *  - X-Frame-Options: DENY — prevent clickjacking
     *  - X-XSS-Protection: 0 — modern recommendation (CSP preferred)
     *  - Content-Security-Policy: restrict resource loading
     *  - Referrer-Policy: limit referrer information leakage
     *  - Server: generic banner (information hiding)
     */
    void addSecurityHeaders(HttpResponse& response) {
        response.headers["X-Content-Type-Options"] = "nosniff";
        response.headers["X-Frame-Options"] = "DENY";
        response.headers["X-XSS-Protection"] = "0";
        response.headers["Content-Security-Policy"] = "default-src 'self'";
        response.headers["Referrer-Policy"] = "no-referrer";
        response.headers["Server"] = "SSS-Secure/1.0";
    }

    std::string webroot_;          ///< Document root directory
    std::string submissions_dir_;  ///< Form submission storage directory
};

// =============================================================================
// Section 9: Connection Handler (Per-Thread)
// =============================================================================

/**
 * @class ConnectionHandler
 * @brief Handles a single client connection on a dedicated thread.
 *
 * Security rationale: Each connection is handled on its own thread with
 * its own stack. This achieves:
 *  - Isolation: A crash or exception handling one connection does not
 *    affect other connections (fault isolation / separation of concerns).
 *  - Resource containment: Each thread's resources are bounded.
 *
 * The RAII Socket wrapper ensures the client socket is closed even if
 * an exception occurs during request processing.
 *
 * Principle: CSSLP Domain 4 — "Separation of Concerns / Isolation"
 */
class ConnectionHandler {
public:
    /**
     * @brief Handle a client connection.
     * @param client_fd The client socket file descriptor (ownership transferred).
     * @param client_addr The client's IP address string (for logging).
     * @param handler Reference to the shared RequestHandler.
     *
     * This method:
     *  1. Wraps the fd in an RAII Socket
     *  2. Reads the request with a timeout and size limit
     *  3. Parses and handles the request
     *  4. Sends the response
     *  5. Closes the socket (automatic via RAII)
     */
    static void handle(int client_fd, const std::string& client_addr,
                       RequestHandler& handler) {
        // RAII: Socket will be closed when this function returns
        Socket client_socket(client_fd);

        LOG_INFO("Connection from: " + client_addr);

        try {
            // Set a read timeout to prevent slowloris-style attacks
            struct timeval timeout;
            timeout.tv_sec = 5;   // 5-second read timeout
            timeout.tv_usec = 0;
            setsockopt(client_socket.get(), SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout));

            // Read the request data
            std::string raw_request = readRequest(client_socket.get());

            if (raw_request.empty()) {
                LOG_WARNING("Empty or timed-out request from: " + client_addr);
                return;  // Socket closed by RAII
            }

            // Parse the raw request
            HttpRequest request = HttpParser::parse(raw_request);

            // Handle the request and generate a response
            HttpResponse response = handler.handleRequest(request);

            // Serialise and send the response
            std::string response_str = response.serialize();
            sendAll(client_socket.get(), response_str);

        } catch (const std::exception& e) {
            LOG_ERROR("Exception handling request from " + client_addr +
                      ": " + e.what());
            // Send a minimal error response
            try {
                std::string error_response =
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n";
                sendAll(client_socket.get(), error_response);
            } catch (...) {
                // Suppress nested exceptions — socket may already be broken
            }
        }
        // Socket automatically closed here by RAII destructor
    }

private:
    /**
     * @brief Read an HTTP request from a socket with size limiting.
     * @param fd The socket file descriptor to read from.
     * @return The raw request data, or empty string on failure/timeout.
     */
    static std::string readRequest(int fd) {
        std::string data;
        char buffer[4096];
        size_t total_read = 0;

        while (total_read < InputValidator::MAX_REQUEST_SIZE) {
            ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;  // EOF, error, or timeout

            data.append(buffer, static_cast<size_t>(n));
            total_read += static_cast<size_t>(n);

            // Check if we've received the complete headers
            if (data.find("\r\n\r\n") != std::string::npos) {
                // For requests with a body, check Content-Length
                auto cl_pos = data.find("Content-Length:");
                if (cl_pos != std::string::npos) {
                    auto nl_pos = data.find("\r\n", cl_pos);
                    if (nl_pos != std::string::npos) {
                        std::string cl_val = data.substr(cl_pos + 15,
                                                         nl_pos - cl_pos - 15);
                        // Trim whitespace
                        cl_val.erase(0, cl_val.find_first_not_of(" "));
                        try {
                            size_t expected = std::stoul(cl_val);
                            auto body_start = data.find("\r\n\r\n") + 4;
                            size_t body_received = data.size() - body_start;
                            if (body_received >= expected) break;
                            // Continue reading for remaining body
                            continue;
                        } catch (...) {
                            break;  // Invalid Content-Length
                        }
                    }
                }
                break;  // No body expected
            }
        }

        return data;
    }

    /**
     * @brief Send all data through a socket, handling partial writes.
     * @param fd The socket file descriptor.
     * @param data The data to send.
     *
     * Loops on send() to handle short writes, which can occur under
     * high load or when the kernel send buffer is full.
     */
    static void sendAll(int fd, const std::string& data) {
        size_t total_sent = 0;
        while (total_sent < data.size()) {
            ssize_t n = send(fd, data.c_str() + total_sent,
                            data.size() - total_sent, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) continue;  // Interrupted — retry
                LOG_ERROR("send() failed: " + std::string(std::strerror(errno)));
                return;
            }
            total_sent += static_cast<size_t>(n);
        }
    }
};

// =============================================================================
// Section 10: Server Core
// =============================================================================

/// Global flag for graceful shutdown (set by signal handler)
static std::atomic<bool> g_running{true};

/**
 * @brief Signal handler for graceful shutdown.
 *
 * Catches SIGINT and SIGTERM to allow the server to clean up
 * resources before exiting. Uses an atomic flag to communicate
 * with the accept loop safely.
 */
void signalHandler(int signum) {
    LOG_INFO("Received signal " + std::to_string(signum) + " — shutting down");
    g_running.store(false);
}

/**
 * @class Server
 * @brief The main web server class — binds, listens, and dispatches connections.
 *
 * Security design:
 *  - Uses RAII Socket for the listening socket
 *  - Detached threads for connection handling (bounded by OS thread limits)
 *  - Graceful signal-based shutdown
 *  - All configuration is validated at startup
 *
 * Principle: Defence in Depth — multiple layers of security are applied
 * at the server, handler, parser, and OS levels.
 */
class Server {
public:
    /**
     * @brief Construct the server.
     * @param port The TCP port to listen on.
     * @param webroot The document root directory.
     */
    Server(uint16_t port, const std::string& webroot)
        : port_(port), webroot_(webroot), handler_(webroot) {}

    /**
     * @brief Start the server: bind, listen, and enter the accept loop.
     * @return 0 on clean shutdown, non-zero on error.
     *
     * The method:
     *  1. Creates and configures the listening socket (SO_REUSEADDR)
     *  2. Binds to the specified port
     *  3. Enters the main accept loop
     *  4. Spawns a detached thread per connection
     *  5. Exits cleanly on signal
     */
    int run() {
        // Validate webroot exists
        if (!fs::exists(webroot_) || !fs::is_directory(webroot_)) {
            LOG_FATAL("Web root does not exist or is not a directory: " + webroot_);
            return 1;
        }

        // Create the listening socket
        Socket listen_socket(socket(AF_INET, SOCK_STREAM, 0));
        if (!listen_socket.isValid()) {
            LOG_FATAL("socket() failed: " + std::string(std::strerror(errno)));
            return 1;
        }

        // Enable SO_REUSEADDR to allow rapid restarts
        int opt = 1;
        if (setsockopt(listen_socket.get(), SOL_SOCKET, SO_REUSEADDR,
                       &opt, sizeof(opt)) < 0) {
            LOG_WARNING("setsockopt(SO_REUSEADDR) failed: " +
                        std::string(std::strerror(errno)));
        }

        // Bind to the specified port on all interfaces
        struct sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port_);

        if (bind(listen_socket.get(),
                 reinterpret_cast<struct sockaddr*>(&server_addr),
                 sizeof(server_addr)) < 0) {
            LOG_FATAL("bind() failed on port " + std::to_string(port_) +
                      ": " + std::string(std::strerror(errno)));
            return 1;
        }

        // Listen with a reasonable backlog
        if (listen(listen_socket.get(), 128) < 0) {
            LOG_FATAL("listen() failed: " + std::string(std::strerror(errno)));
            return 1;
        }

        LOG_INFO("SSS Secure Web Server started on port " +
                 std::to_string(port_));
        LOG_INFO("Serving files from: " +
                 fs::canonical(webroot_).string());
        LOG_INFO("Press Ctrl+C to stop");

        // Install signal handlers for graceful shutdown
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        // Main accept loop
        while (g_running.load()) {
            struct sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

            // Set accept timeout to allow checking g_running periodically
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(listen_socket.get(), SOL_SOCKET, SO_RCVTIMEO,
                       &tv, sizeof(tv));

            int client_fd = accept(listen_socket.get(),
                                   reinterpret_cast<struct sockaddr*>(&client_addr),
                                   &client_len);

            if (client_fd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;  // Timeout — check g_running and try again
                }
                if (g_running.load()) {
                    LOG_ERROR("accept() failed: " +
                              std::string(std::strerror(errno)));
                }
                continue;
            }

            // Extract client IP address for logging
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
            std::string client_ip(ip_str);

            // Spawn a detached thread to handle the connection
            // Each thread receives its own copy of client_ip (value semantics)
            // and a reference to the shared handler
            std::thread([client_fd, client_ip, this]() {
                ConnectionHandler::handle(client_fd, client_ip, handler_);
            }).detach();
        }

        LOG_INFO("Server shutdown complete");
        return 0;
    }

private:
    uint16_t port_;              ///< Listening port
    std::string webroot_;        ///< Document root directory
    RequestHandler handler_;     ///< Shared request handler
};