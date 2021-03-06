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
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <signal.h>
    #include <sys/un.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <netdb.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <set>
#include <map>
#include <unordered_map>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
    #pragma comment(lib,"ws2_32.lib")
    #pragma comment(lib,"libcrypto.lib")
    #pragma comment(lib,"libssl.lib")
#endif

typedef std::unordered_map<int, std::string> fd_desc_map_t;
typedef std::unordered_map<int, int> fd_port_map_t;

#define CUSTOM_EXT_TYPE_1000 10000
#define PROTO_HEAD_SIZE     12
#define USER_MSG_SIZE    81920

typedef struct {
    std::string ssl_host;
    int ssl_port;
    bool verify_peer;
    bool connected;
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
} ssl_conn_t;

void init_openssl();
void cleanup_ssl(ssl_conn_t *ssl_conn);
int server_open_socket(int port, fd_port_map_t &port_map);
int client_open_ssl(ssl_conn_t *ssl_con);
int init_ssl_config(ssl_conn_t *ssl_config);
int handle_ssl_read(ssl_conn_t *ssl_con);
int handle_read_client(int fd, ssl_conn_t *ssl_con, fd_port_map_t &port_map);
int handle_accept(int fd, fd_port_map_t &port_map);

int exact_write(int fd, void *buffer, int length);
int ssl_exact_write(SSL *ssl, void *buffer, int length);
int ssl_exact_read(SSL *ssl, void *buffer, int length);

#endif /* HELP_H_ */
