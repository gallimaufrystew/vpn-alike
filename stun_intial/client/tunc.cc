///
/// File:   tunnels.c
/// Author: xingkanhu
///

#include "tunc_help.h"
#include "config.h"

#ifdef _WIN32
    #include "openssl\applink.c"
#endif

int event_process(fd_set *fdset, ssl_conn_t *ssl_conn,std::map<int,bool> &conns,
                  fd_desc_map_t &fd_desc_map,fd_port_map_t &fd_port_map);
int handle_client_event(int fd, ssl_conn_t *ssl_conn,fd_desc_map_t &fd_desc_map,
                        fd_port_map_t &fd_port_map,std::map<int,bool> &conns);

extern std::map<int,bool> connections;
extern conf_map_t conf_map;

int main(int argc, char *argv[])
{
    int maxfd = -1;
    bool running = true;
    fd_set fdset;

    fd_desc_map_t fd_desc_map;
    fd_port_map_t fd_port_map;

#ifdef _WIN32
    WSADATA  ws_data;
    if (WSAStartup(MAKEWORD(2, 2), &ws_data)) {
        fprintf(stderr, "WSAStartup() fail: %d\n", GetLastError());
        return -1;
    }
#endif

    init_listen_port();

    ssl_conn_t ssl_conn;
    init_ssl_config(&ssl_conn);

    client_open_ssl(&ssl_conn);

    connections[ssl_conn.fd] = true;

    fd_desc_map[ssl_conn.fd] = "ssl";

	auto it = conf_map.equal_range("listen").first;
    for (; it != conf_map.equal_range("listen").second; ++it) {
        std::cout << "listen on:" << it->second.first << "\n";
        int fd = server_open_socket(it->second.first, fd_port_map);
		maxfd = std::max(maxfd,fd);
        connections[fd] = true;
        fd_desc_map[fd] = "listen";
    }

#ifndef _WIN32
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;

    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, 0);
#endif

    std::cout << "start handling event...\n";

    struct timeval tv;

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
            //printf("%ld elapsed,timeout\n", timeout);
        } else if (ret < 0) {
			std::cout << "select x" << strerror(errno) << "\n";
		} else {
            event_process(&fdset, &ssl_conn, connections, fd_desc_map,fd_port_map);
        }
    }

    cleanup_ssl(&ssl_conn);

    for (auto it = connections.begin(); it != connections.end(); ++it) {
        close(it->first);
    }

	connections.clear();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

int event_process(fd_set *fdset, ssl_conn_t *ssl_conn,
                  std::map<int,bool> &conns, fd_desc_map_t &fd_desc_map,
                  fd_port_map_t &fd_port_map)
{
	for (auto it = conns.begin(); it != conns.end(); ++it) {

        if (it->second == false) {
            continue;
        }

        if (FD_ISSET(it->first, fdset)) {
            if (it->first == ssl_conn->fd) {
                handle_ssl_read(ssl_conn);
            } else {
                handle_client_event(it->first, ssl_conn, fd_desc_map, fd_port_map, conns);
            }
        }
    }

    return 0;
}

int handle_client_event(int fd, ssl_conn_t *ssl_conn,
                        fd_desc_map_t &fd_desc_map, fd_port_map_t &fd_port_map,
                        std::map<int,bool> &conns)
{
    auto it = fd_desc_map.find(fd);
    if (it != fd_desc_map.end()) {

        if (it->second == "listen") {

            int sock = 0;
            sock = handle_accept(fd, fd_port_map);
            if (sock > 0) {

                printf(" -- accept success on %d client %d --\n", fd, sock);

                fd_desc_map[sock] = "client";
				conns[sock] = true;

				if (fd_port_map[sock] == 1031 || fd_port_map[sock] == 1032) {

					char cmd[] = "RFB_OPEN";
                    char buf[PROTO_HEAD_SIZE + 128];

					sprintf(buf,"%s%s","111111111111",cmd);

                    uint32_t len = strlen(cmd), nlen;
                    nlen = htonl(len);
                    memcpy(buf, &nlen, 4);

                    uint32_t port = fd_port_map[sock], nport;
                    nport = htonl(port);
                    memcpy(buf + 4, &nport, 4);

                    uint32_t nfd;
                    nfd = htonl(sock);
                    memcpy(buf + 8, &nfd, 4);

                    ssl_exact_write(ssl_conn->ssl, buf, PROTO_HEAD_SIZE + len);
                }
            }
        } else {

            handle_read_client(fd, ssl_conn, fd_port_map);
        }
    }

    return 0;
}
