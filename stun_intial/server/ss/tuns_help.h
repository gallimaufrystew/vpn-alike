///
/// help.h
///

#ifndef HELP_INCLUDED_H_
#define HELP_INCLUDED_H_

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
#else
    #include <signal.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/un.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/time.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <stdbool.h>
    #include <string.h>
    #include <iostream>
    #include <string>
    #include <set>
    #include <map>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
    #include "openssl\applink.c"
#endif

#define CUSTOM_EXT_TYPE_1000 10000

#define PROTO_HEAD_SIZE     12
#define USER_MSG_SIZE    81920

typedef struct {
    bool verify_peer;
    bool connected;
    unsigned int connected_count;
    int fd;
    SSL *ssl;
    int client;
    SSL_CTX *ssl_old_ctx;
    SSL_CTX *ssl_new_ctx;
} ssl_session_t;

int open_socket(int port);
int open_upstream(int port);
int init_libssl();
void cleanup_ssl(ssl_session_t *ssls);
int open_ssl(int port);
SSL_CTX *create_ssl_ctx(const char *sign_algo);
int create_ssl_context(ssl_session_t *session);
int handle_ssl_accept_client(ssl_session_t *session);
int handle_ssl_read(ssl_session_t *session);
int handle_upstream_read(int fd, ssl_session_t *session);

#endif /* HELP_H_ */
