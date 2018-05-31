/*
 * File:   tun_socket.h
 * Author: xingkanhu
 *
 * Created on April 11, 2016
 */

#ifndef STUNC_SOCKET_INCLUDED_H
#define STUNC_SOCKET_INCLUDED_H

#if __linux__
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
#elif _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
#endif

#pragma warning(disable: 4996)

#include <cstdio>
#include <iostream>

#define SOCK_TIMEOUT   60
#define SOCK_BUF_SIZE  16*1024

#if __linux__
#define SOCKET_ERROR -1
#endif

int funnel_setsockopt(int sock);
int socket_nonblock(int fd);
int socket_block(int fd);
int timeout_connect(int fd, struct sockaddr *addr, socklen_t sock_len);
void close_sock(int fd);

#endif /* TUN_SOCKET_INCLUDED_H */
