///
/// File:   tuns.c
/// Author: xingkanhu
///

#include "tuns_core.h"
#include "tun_signal.h"
#include "config.h"

#ifdef _WIN32
#include "openssl\applink.c"
#endif

int event_process(fd_set *fdset, std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session);
int handle_read_ssl_client(std::unordered_map<int,bool> &conns, ssl_session_t *ssl_session);
int handle_ssl_accept_event(std::unordered_map<int,bool> &conns, ssl_session_t *ssl_session);

extern std::unordered_map<int, bool> connections;

int main(int argc, char *argv[])
{
    int maxfd = -1;
    fd_set fdset;
    struct timeval tv = {};

    ssl_session_t ssl_session = {};
    ssl_session.verify_peer = false;
    ssl_session.connected = false;
    ssl_session.connected_count = 0;
    
    init_signal();

    maxfd = ssl_session.fd = init_ssl_service();

    std::cout << "ssl fd " << ssl_session.fd << "\n";

    connections[ssl_session.fd] = true;

    std::cout << "start handling event...\n";

    while (running) {

        FD_ZERO(&fdset);

        for (auto it = connections.begin(); it != connections.end(); ++it) {
            if (it->second) {
                // we don't want to block forever
                tv.tv_sec = 30;
                tv.tv_usec = 0;
                setsockopt(it->first,SOL_SOCKET,SO_RCVTIMEO,(char *)&tv, sizeof(tv));
                setsockopt(it->first,SOL_SOCKET,SO_SNDTIMEO,(char *)&tv, sizeof(tv));
                maxfd = std::max(maxfd, it->first);
                FD_SET(it->first, &fdset);
            }
        }

        tv.tv_sec = 1000;
        tv.tv_usec = 0;

        int ret = select(maxfd + 1, &fdset, nullptr, nullptr, &tv);
        if (ret == 0) {
            // timeoout
        } else if (ret < 0 ) {
            std::cout << "select: " << strerror(errno) << "\n";
        } else {
            event_process(&fdset, connections, &ssl_session);
        }
    }

    clean_up(&ssl_session);

    return 0;
}

int event_process(fd_set *fdset, std::unordered_map<int,bool> &conns, ssl_session_t *ssl_session)
{
     for (auto it = conns.begin(); it != conns.end(); ++it) {

        if (it->second == false) {
            continue;
        }

        if (FD_ISSET(it->first, fdset)) {

            if (it->first == ssl_session->fd) {
                handle_ssl_accept_event(conns, ssl_session);
            } else if (it->first == ssl_session->client) {
                handle_read_ssl_client(conns, ssl_session);
            } else {
                handle_upstream_read(it->first, ssl_session);
            }
        }
    }

    return 0;
}

int handle_ssl_accept_event(std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session)
{
    if (!ssl_session->connected) {

        if (ssl_session->connected_count) {
            // cleanup previously claimed resources
            clean_up_ssl(ssl_session);
        }

        handle_ssl_accept_client(ssl_session);
        conns[ssl_session->client] = true;

    } else {
        // only one
        int fd = accept(ssl_session->fd, nullptr, 0);
        if (fd > 0) {
            close(fd);
        }
    }

    return 0;
}

int handle_read_ssl_client(std::unordered_map<int,bool> &conns, ssl_session_t *ssl_session)
{
    return handle_ssl_read(ssl_session);
}
