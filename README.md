# sss-secure-webserver

================================================================================
SSS Secure Web Server --- Compile Instructions
================================================================================

Platform: Linux (Fedora VM as provided) Language: C++17 Compiler: GCC
(g++) or Clang (clang++)

  --------------
   Dependencies
  --------------

1.  GCC/G++ (version 8+ for C++17 support)
    -   Included with Fedora: gcc, gcc-c++
    -   Version tested: gcc 13.x (Fedora 39/40)
2.  libseccomp (for seccomp-bpf sandboxing)
    -   Package: libseccomp-devel
    -   Version: 2.5.x
    -   Source: https://github.com/seccomp/libseccomp
    -   Install: sudo dnf install libseccomp-devel
3.  POSIX threads (pthreads)
    -   Included with glibc on Linux
4.  C++ Standard Library with `<filesystem>`{=html} support
    -   Included with gcc 8+ / clang 7+ on Fedora

  ------------------
   Compile Commands
  ------------------

Using GCC (recommended):

    g++ -std=c++17 -Wall -Wextra -Werror -O2 \
        -o sss_server src/server.cpp \
        -lpthread -lseccomp

Using Clang:

    clang++ -std=c++17 -Wall -Wextra -Werror -O2 \
        -o sss_server src/server.cpp \
        -lpthread -lseccomp

Debug build (with sanitizers):

    g++ -std=c++17 -Wall -Wextra -g -fsanitize=address,undefined \
        -o sss_server_debug src/server.cpp \
        -lpthread -lseccomp

  --------------------
   Running the Server
  --------------------

    ./sss_server [port] [webroot]

    Default: port=8080, webroot=./www

    Examples:
        ./sss_server                    # port 8080, webroot ./www
        ./sss_server 9090               # port 9090, webroot ./www
        ./sss_server 8080 /var/www      # port 8080, webroot /var/www

    The server logs to stderr and to sss_server.log in the working directory.
    Press Ctrl+C to stop the server gracefully.

  ---------
   Testing
  ---------

    # Test GET request
    curl http://localhost:8080/

    # Test file from subdirectory
    curl http://localhost:8080/subdir/nested.html

    # Test 404
    curl http://localhost:8080/nonexistent.html

    # Test POST form submission
    curl -X POST -d "name=Test&email=test@example.com&message=Hello" \
         http://localhost:8080/submit

    # Test path traversal prevention
    curl --path-as-is http://localhost:8080/../../etc/passwd
    # Expected: 404 Not Found

    # Test HEAD request
    curl -I http://localhost:8080/

================================================================================
