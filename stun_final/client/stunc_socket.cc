/*
* stunc_socket.cc
*/

#include "stunc_socket.h"

int funnel_setsockopt(int sock)
{
	int ret;
	int optVal = SOCK_BUF_SIZE;
    socklen_t optLen = sizeof(int);

	ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&optVal, optLen);
    if (ret == SOCKET_ERROR) {
        //printf("setsockopt SO_SNDBUF error: %u\n", WSAGetLastError());
		return -1;
    }

	ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&optVal, &optLen);
	if (ret == SOCKET_ERROR) {
		//printf("SockOpt Value: %ld\n", optVal);
		return -1;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&optVal, optLen);
    if (ret == SOCKET_ERROR) {
        //printf("setsockopt SO_SNDBUF error: %u\n", WSAGetLastError());
		return -1;
    }

	ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&optVal, &optLen);
	if (ret == SOCKET_ERROR) {
		//printf("SockOpt Value: %ld\n", optVal);
		return -1;
	}
	
	struct timeval tv = {SOCK_TIMEOUT, 0};
	
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

	return 0;
}

#if __linux__

#if (HAVE_IOCTL)

/* if possible call ioctl
 * save one system call
 */
int socket_nonblock(int fd)
{
    int nb = 1;
    return ioctl(fd, FIONBIO, &nb);
}

int socket_block(int fd)
{
    int nb = 0;
    return ioctl(fd, FIONBIO, &nb);
}

#else

/* fcntl, standardized by POSIX
 * call this function for consistent behavior
 */
int atun_ioctl(int fd, bool non_block)
{

    int flags;

    /* Set the socket blocking (if non_block is zero) or non-blocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal.
     */
    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        return -1;
    }

    if (non_block) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    if (fcntl(fd, F_SETFL, flags) == -1) {
        return -1;
    }
    return 0;
}

int socket_nonblock(int fd)
{
    return atun_ioctl(fd, true);
}

int socket_block(int fd)
{
    return atun_ioctl(fd, false);
}

#endif

#elif _WIN32

int socket_nonblock(int fd)
{
    unsigned long  nb = 1;
    return ioctlsocket(fd, FIONBIO, &nb);
}

int socket_block(int fd)
{
    unsigned long  nb = 0;

    return ioctlsocket(fd, FIONBIO, &nb);
}

#endif

static int check_connect(int fd)
{
    for (;;) {

        fd_set wset;

        FD_ZERO(&wset);
        FD_SET(fd, &wset);

        struct timeval tv = {10, 0};

        int res = select(fd + 1, NULL, &wset, NULL, &tv);
        if (res < 0 && errno != EINTR) {
            std::fprintf(stderr, "|select| %d - %s\n", errno, strerror(errno));
            return -1;
        } else if (res > 0) {
            int val;
            socklen_t len = sizeof(int);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)(&val), &len) < 0) {
                std::fprintf(stderr, "|getsockopt| %d - %s\n", errno, strerror(errno));
                return -1;
            }
            if (val) {
                fprintf(stderr, "|getsockopt=| %d - %s\n", val, strerror(val));
                return -1;
            }
            break;
        }
    }

    return 0;
}

int timeout_connect(int fd, struct sockaddr *addr, socklen_t sock_len)
{
    socket_nonblock(fd);

#if (0)
    /*
    int ret = -1;

    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        timeval tm;
        fd_set set;

        tm.tv_sec  = 5;
        tm.tv_usec = 0;

        FD_ZERO(&set);
        FD_SET(fd, &set);

        int error=-1, len;
        len = sizeof(int);

        if (select(fd + 1, NULL, &set, NULL, &tm) > 0)
        {
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&error, (socklen_t *)&len);
            if(error == 0) ret = 0;
            //else ret = false;
        } //else ret = false;
    }
    else ret = 0;

    //socket_block(fd);

    if(ret)
    {
        close_sock( fd );
        fprintf(stderr , "Cannot Connect the server!\n");
        return ret;
    }
    fprintf( stderr , "Connected!\n");

    socket_block(fd);

    return ret;

    /*
    socket_nonblock(fd);

    int rc = connect(fd, addr, sock_len);

    printf("rc =============== %d\n", rc);

    if (rc != 0) {

    if (errno == EINPROGRESS || errno == EWOULDBLOCK) {

    fd_set rset, wset;
    struct timeval tv = {10, 0};

    FD_ZERO(&rset);
    FD_ZERO(&wset);

    FD_SET(fd, &rset);
    FD_SET(fd, &wset);

    rc = select(fd + 1, nullptr, &wset, nullptr, &tv);
    if (rc < 0) {
    std::fprintf(stderr, "111 : %s\n", strerror(errno));
    close_sock(fd);
    return -1;
    }

    if (rc == 0) {
    std::fprintf(stderr, "timeout\n");
    return -1;
    }

    if (rc == 1 && FD_ISSET(fd, &wset)) {
    int err;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &len) == -1) {
    std::fprintf(stderr, "222 : %s", strerror(errno));
    close_sock(fd);
    return -1;
    }
    if (err) {
    //errno = err;
    std::fprintf(stderr, "333 : %s\n", strerror(errno));
    //close_sock(fd);

    //socket_block(fd);

    return -1;
    }

    std::cout << "connect success\n";
    socket_block(fd);
    return 0;
    } else if (rc == 2) {

    }
    }

    std::fprintf(stderr, "555 : %s\n", strerror(errno));

    if (errno == 0) {
    socket_block(fd);
    return 0;
    }
    }

    socket_block(fd);

    return 0;
    */
#endif

#if (1)
    int rc = connect(fd, addr, sock_len);
    if (rc == SOCKET_ERROR) {
#if _WIN32
        int err = WSAGetLastError();
#elif __linux__
        int err = errno;
#endif
        if (err == EINPROGRESS 
#if _WIN32
            || err == WSAEWOULDBLOCK
#endif
        ) {

            if (check_connect(fd) != 0) {
                return -1;
            }

        } else if (err == 0) {
            socket_block(fd);
            return 0;
        } else {
            std::fprintf(stderr, "|connect| %d - %s\n", errno, strerror(errno));
            return -1;
        }
    }
    socket_block(fd);

    return 0;
#endif

}

void close_sock(int fd)
{
#if __linux__
    close(fd);
#elif _WIN32
    closesocket(fd);
#endif
}
