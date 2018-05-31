///
/// File:   tunnels.c
/// Author: xingkanhu
///

#include "tuns_help.h"

int event_process(fd_set *fdset, std::map<int,bool> &conns, ssl_session_t *ssl_session);
int handle_read_ssl_client(std::map<int,bool> &conns, ssl_session_t *ssl_session);
int handle_ssl_accept_event(std::map<int,bool> &conns, ssl_session_t *ssl_session);

extern std::map<int,bool> connections;

int main(int argc, char *argv[])
{
    int maxfd = -1;
    bool running = true;
    fd_set fdset;
    struct timeval tv;
    struct sigaction sa;

    ssl_session_t ssl_session;
    ssl_session.verify_peer = false;
    ssl_session.connected = false;
    ssl_session.connected_count = 0;

    maxfd = ssl_session.fd = open_ssl(443);

    std::cout << "ssl fd " << ssl_session.fd << "\n";

    std::cout << "start handling event..." << "\n";

    connections[ssl_session.fd] = true;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, 0);

    while (running) {

        FD_ZERO(&fdset);

        for (auto it = connections.begin(); it != connections.end(); ++it) {
            if (it->second) {
                maxfd = std::max(maxfd, it->first);
                FD_SET(it->first, &fdset);
            }
        }

        tv.tv_sec = 1000;
        tv.tv_usec = 0;

        int ret = select(maxfd + 1, &fdset, nullptr, nullptr, &tv);
        if (ret == 0) {
            //timeoout
        } else if (ret < 0 ) {
            std::cout << "select error\n";
        } else {
            event_process(&fdset, connections, &ssl_session);
        }
    }

    cleanup_ssl(&ssl_session);

    for (auto it = connections.begin(); it != connections.end(); ++it) {
        close(it->first);
    }

    connections.clear();

    return 0;
}

int event_process(fd_set *fdset, std::map<int,bool> &conns, ssl_session_t *ssl_session)
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

int handle_ssl_accept_event(std::map<int,bool> &conns, ssl_session_t *ssl_session)
{
    if (!ssl_session->connected) {

        if (ssl_session->connected_count) {
            // cleanup previously claimed resources
            cleanup_ssl(ssl_session);
        }

        handle_ssl_accept_client(ssl_session);
        conns[ssl_session->client] = true;

        ssl_session->connected_count = 1;
        
    } else {
        // only one
        int fd = accept(ssl_session->fd, nullptr, 0);
        if (fd > 0) {
            close(fd);
        }
    }

    return 0;
}

int handle_read_ssl_client(std::map<int,bool> &conns, ssl_session_t *ssl_session)
{
    handle_ssl_read(ssl_session);
    return 0;
}
