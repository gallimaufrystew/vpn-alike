
/*
 * File:   atun_sys_config.h
 * Author: 19020107
 *
 * Created on April 30, 2018, 12:06 AM
 */

#ifndef ATUN_CONFIG_H
#define ATUN_CONFIG_H

#if __linux__

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdint.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #include <errno.h>
    #include <signal.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/epoll.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/un.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/wait.h>
    #include <sys/time.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <stdbool.h>
    #include <string.h>
    #include <cstdio>
    #include <cstring>
    #include <iostream>
    #include <string>
    #include <sstream>
    #include <fstream>
    #include <list>
    #include <map>
    #include <unordered_set>
    #include <deque>
    #include <queue>
    #include <unordered_map>

#elif _WIN32

    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
    #include "openssl\applink.c"

#endif

typedef int         atun_err_t;
typedef intptr_t    atun_int_t;
typedef uintptr_t   atun_uint_t;

#define ATUN_CONFIG_BACKLOG  5

#endif /* ATUN_CONFIG_H */
