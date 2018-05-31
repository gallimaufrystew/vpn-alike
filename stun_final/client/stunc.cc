///
/// File:   tunc.c
/// Author: xingkanhu
///

#include "stunc_core.h"
#include "stunc_config.h"
#include "stunc_socket.h"

#if __linux__
#elif _WIN32
    #include "openssl\applink.c"
#endif

int event_process(fd_set &rset, ssl_conn_t &ssl_conn, uid2fd_map_t &conns,
                  fd_desc_map_t &fd_desc_map, fd_port_map_t &fd_port_map);
int handle_client_event(int fd, ssl_conn_t &ssl_conn, fd_desc_map_t &fd_desc_map,
                        fd_port_map_t &fd_port_map, uid2fd_map_t &conns);

extern uid2fd_map_t connections;
extern config_map_t config_map;
extern fd2uid_map_t fd2uid;

int main(int argc, char *argv[])
{
    fd_set rset;
    fd_desc_map_t fd_desc_map;
    fd_port_map_t fd_port_map;
    int maxls = -1;

    init_signal();

    init_listen_port();

    ssl_conn_t ssl_conn = {};
    init_ssl_config(ssl_conn);

    init_openssl();

    auto it = config_map.equal_range("listen").first;
    for (; it != config_map.equal_range("listen").second; ++it) {
        std::cout << "listen on:" << it->second.first << "\n";
        int fd = server_open_socket(it->second.first, fd_port_map);
        maxls = std::max(maxls, fd);
        int suid = retrieve_session_id();
        connections[suid] = std::make_pair(fd, true);
        fd_desc_map[fd] = "listen";
    }

    std::cout << "start handling event...\n";

    struct timeval tv;

    for (;;) {

        if (sig_exit) {
			std::cout << "ctrl + c received\n";
            break;
        }

        if (!ssl_conn.connected) {
            if (ssl_conn.fd > 0) {
                cleanup_ssl(ssl_conn);
            }
            if (client_open_ssl(ssl_conn) < 0) {
                continue;
            }
            connections[1] = std::make_pair(ssl_conn.fd, true);
            fd_desc_map[ssl_conn.fd] = "ssl";
        }

        FD_ZERO(&rset);

        int valid_fds = 0, maxfd = 0;

        for (auto it = connections.begin(); it != connections.end(); ++it) {
            auto fd_state = it->second;
            if (fd_state.second) {

                int       n;
                socklen_t len = sizeof(int);

                if (getsockopt(fd_state.first, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
                    //FD_CLR(fd_state.first, &rset);
                    //close_sock(fd_state.first);
                    connections[it->first] = std::make_pair(fd_state.first, false);
                    continue;
                }

				funnel_setsockopt(fd_state.first);

                maxfd = std::max(maxfd, fd_state.first);
                FD_SET(fd_state.first, &rset);
                valid_fds ++;
            } else {
                //close_sock(fd_state.first);
                //connections[it->first] = std::make_pair(fd_state.first,false);
            }
        }

        maxfd = std::max(maxfd, maxls);

        if (0) {

            waste_time(1000);

            continue;
        }

        tv.tv_sec = 1000;
        tv.tv_usec = 0;

        int ret = select(maxfd + 1, &rset, nullptr, nullptr, &tv);
        if (ret == 0) {
            std::cout << "no active event\n";
        } else if (ret < 0) {
            //std::cout << "select ERR: " << strerror(errno) << "\n";
        } else {
            event_process(rset, ssl_conn, connections, fd_desc_map, fd_port_map);
        }
    }

    fd_desc_map.clear();
    fd_port_map.clear();
    clean_up(ssl_conn);

    return 0;
}

int event_process(fd_set &rset, ssl_conn_t &ssl_conn,
                  uid2fd_map_t &conns, fd_desc_map_t &fd_desc_map,
                  fd_port_map_t &fd_port_map)
{
    for (auto it = conns.begin(); it != conns.end(); ++it) {

        auto fd_state = it->second;
        if (fd_state.second == false) {
            continue;
        }

        if (FD_ISSET(fd_state.first, &rset)) {
            if (fd_state.first == ssl_conn.fd) {
                handle_ssl_read(ssl_conn);
            } else {
                handle_client_event(fd_state.first, ssl_conn,
                                    fd_desc_map, fd_port_map, conns);
            }
        }
    }

    return 0;
}

static int send_command(int suid, ssl_conn_t &ssl_conn,
                            fd_desc_map_t &fd_desc_map,
                            fd_port_map_t &fd_port_map,
                            uid2fd_map_t &conns)
{
    int fd = conns[suid].first;
    if (fd_port_map[fd] == 1032 || fd_port_map[fd] == 1033) {

        char command[] = "OPEN_CONNECTION";
        char buf[PROTO_HEAD_SIZE + 128];

        std::memcpy(buf + 12, command, std::strlen(command));

        uint32_t len = std::strlen(command), nlen;
        nlen = htonl(len);
        std::memcpy(buf, &nlen, 4);

        uint32_t port = fd_port_map[fd], nport;
        nport = htonl(port);
        std::memcpy(buf + 4, &nport, 4);

        uint32_t nsuid;
        nsuid = htonl(suid);
        std::memcpy(buf + 8, &nsuid, 4);

        int n = ssl_exact_write(ssl_conn.ssl, buf, PROTO_HEAD_SIZE + len);
        if (n != 0) {
            ssl_conn.connected = false;
            //conns[1] = std::make_pair(ssl_conn.fd,false);
        }
    }

    return 0;
}

int init_client(int fd, ssl_conn_t &ssl_conn,
                fd_desc_map_t &fd_desc_map,
                fd_port_map_t &fd_port_map,
                uid2fd_map_t &conns)
{
    fd_desc_map[fd] = "client";

    uint32_t suid = retrieve_session_id();

    std::cout << ">>> session id " << suid << "\n\n";

    conns[suid] = std::make_pair(fd, true);
    fd2uid[fd] = std::make_pair(suid, true);

    send_command(suid, ssl_conn, fd_desc_map, fd_port_map, conns);

    return 0;
}

int handle_client_event(int fd, ssl_conn_t &ssl_conn,
                        fd_desc_map_t &fd_desc_map,
                        fd_port_map_t &fd_port_map,
                        uid2fd_map_t &conns)
{
    auto it = fd_desc_map.find(fd);
    if (it != fd_desc_map.end()) {
        if (it->second == "listen") {
            int sock = handle_accept(fd, fd_port_map);
            if (sock > 0) {
                std::cout << ">> accept on " << fd << " <> " << sock << "\n";
                init_client(sock, ssl_conn, fd_desc_map, fd_port_map, conns);
            }
        } else {
            handle_read_client(fd, ssl_conn, fd_port_map);
        }
    }

    return 0;
}
