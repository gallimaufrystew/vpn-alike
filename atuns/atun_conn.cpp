
#include "atun_conn.h"
#include "atun_ssl.h"
#include "atun_config.h"

static atun_conn_list    fixed_conns;
static atun_conn_t *lconn, *sslconn;

extern port_map_t        port_map;
extern atun_chain_map_t  chains_map;
extern atun_conn_map_t   conns_map;
extern atun_chain_t      ssl_send_chain, ssl_recv_chain;

atun_int_t atun_handle_event_accept(atun_event_t *ev);

static atun_int_t atun_accept(atun_sock_t s);

atun_int_t atun_add_accept_event(atun_sock_t ls)
{
    atun_set_nonblock(ls);

    lconn = atun_retrieve_conn();
    if (lconn == nullptr) {
        // fatal...
        return ATUN_ERROR;
    }

    lconn->fd = ls;
    lconn->read_event->accept = 1;
    lconn->read_event->write = 0;
    lconn->read_event->handler = atun_handle_event_accept;

    atun_add_event(lconn->read_event, ATUN_READ_EVENT, 0);

    return ATUN_OK;
}

void atun_free_ls_conn()
{
    if (lconn) {
        atun_free_conn(lconn);
    }
    lconn = nullptr;
}

void atun_free_ssl_conn()
{
    if (sslconn) {
        atun_free_conn(sslconn);
    }
    sslconn = nullptr;
}

atun_int_t
atun_add_tunnel_event(atun_sock_t ssl_fd)
{
    sslconn = atun_retrieve_conn();
    if (sslconn == nullptr) {
        // fatal...
        return ATUN_ERROR;
    }

    sslconn->fd = ssl_fd;
    sslconn->read_event->accept = 0;
    sslconn->read_event->write = 0;
    sslconn->read_event->handler = atun_handle_ssl_handshake;

    atun_add_event(sslconn->read_event, ATUN_READ_EVENT, 0);

    return ATUN_OK;
}

atun_int_t
atun_handle_event_accept(atun_event_t *ev)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);
    atun_int_t fd = atun_accept(c->fd);
    if (fd <= 0) {
        return ATUN_ERROR;
    }

    std::cout << "ssl fd " << fd << "\n";

    atun_set_nonblock(fd);

    atun_int_t ret = atun_ssl_session_init(fd);
    if (ret != 0) {
        return ATUN_ERROR;
    }

    atun_add_tunnel_event(fd);

    return ATUN_OK;
}


static atun_int_t
atun_accept(atun_sock_t s)
{
    atun_int_t fd;

    for (;;) {
        fd = accept(s, nullptr, 0);
        if (fd == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                // fatal...
                return ATUN_ERROR;
            }
        }
        break;
    }
    return fd;
}

atun_conn_t *atun_retrieve_conn()
{
    atun_conn_t *c = nullptr;

    if (fixed_conns.empty()) {
        return c;
    }

    c = fixed_conns.front();
    fixed_conns.pop_front();

    c->read_event->instance = 1;
    c->read_event->index = ATUN_INVALID_INDEX;

    c->write_event->instance = 1;
    c->write_event->index = ATUN_INVALID_INDEX;

    c->eof = 0;
    c->peer = nullptr;

#if (0)
    atun_event_t *rev = c->read_event;
    rev->instance = !rev->instance;

    atun_event_t *wev = c->write_event;
    wev->instance = !wev->instance;

    memset(c, 0, sizeof(atun_conn_t));

    c->read_event = rev;
    c->write_event = wev;
#endif

    return c;
}

void atun_free_all_conns()
{
    for (auto it = conns_map.begin(); it != conns_map.end(); ++it) {
        atun_free_conn(it->second.first);
    }
    conns_map.clear();
}

void atun_free_conn(atun_conn_t *c)
{
    fixed_conns.push_back(c);
}

void atun_conn_init(atun_int_t max_conns)
{
    size_t conn_size = sizeof(atun_conn_t);
    size_t event_size = sizeof(atun_event_t);

    for (atun_int_t i = 0; i < max_conns; ++i) {

        atun_conn_t *c = static_cast<atun_conn_t *>(atun_alloc(conn_size));
        if (c == nullptr) {
            // fatal...
            return;
        }

        c->read_event = static_cast<atun_event_t *>(atun_alloc(event_size));
        if (c->read_event == nullptr) {
            // fatal...
            return;
        }
        c->read_event->data = c;
        c->read_event->instance = 1;
        c->read_event->index = ATUN_INVALID_INDEX;

        c->write_event = static_cast<atun_event_t *>(atun_alloc(event_size));
        if (c->write_event == nullptr) {
            // fatal...
            return;
        }
        c->write_event->data = c;
        c->write_event->instance = 1;
        c->write_event->index = ATUN_INVALID_INDEX;

        fixed_conns.push_back(c);
    }
}

void atun_finalize_conn(atun_conn_t *c)
{
    std::cout << "finalize..." << "\n";

    // free connection > when...
    c->eof = 1;

    atun_del_conn(c, 0);

    atun_close_sock(c->fd);

    auto it = chains_map[c->suid].begin();
    for (; it != chains_map[c->suid].end(); ++it) {
        atun_alloc_free(it->first);
    }
    chains_map[c->suid].clear();
}

void atun_add_ssl_write_event(atun_conn_t *uc)
{
    atun_conn_t *peer = uc->peer;

    if (!peer->write_event->active) {
        peer->write_event->handler = atun_handle_ssl_write;
        peer->write_event->write = 1;
        atun_add_event(peer->write_event, ATUN_WRITE_EVENT, 0);
    }
}

atun_int_t atun_handle_upstream_read(atun_event_t *ev)
{
    atun_conn_t *uc = static_cast<atun_conn_t *>(ev->data);

    ssize_t  n;

    u_char buf[ATUN_DATA_SIZE] = {};

    //std::cout << "read from..........." << uc->fd << "\n";

    //do {
    n = recv(uc->fd, buf + ATUN_PROTO_SIZE, ATUN_DATA_SIZE - ATUN_PROTO_SIZE, 0);

    std::cout << "             upstream size <<<<<<< " << n << "\n";

    if (n > 0) {

        int32_t  nlen;
        nlen = htonl(n);
        memcpy(buf, &nlen, 4);

        ////////////////////////////////
        /// ignore this field

        int32_t nsuid;
        nsuid = htonl(uc->suid);
        memcpy(buf + 8, &nsuid, 4);

        size_t size = n + ATUN_PROTO_SIZE;

        u_char *data = (u_char *)atun_alloc(size);
        std::memcpy(data, buf, size);
        ssl_send_chain.push_back(std::make_pair(data, size));

        atun_add_ssl_write_event(uc);

        return ATUN_OK;
    }

    if (errno == EAGAIN || errno == EINTR) {

        std::cout << "atun_upstream_read recoverable...." << errno << "\n";

        return ATUN_AGAIN;
    }

    std::cout << "atun_upstream_read fatal...." << errno << "\n";

    //if (n == 0) {
    //close(uc->fd);
    //    return n;
    //}

    //if (errno == EAGAIN || errno == EINTR) {
    // can retry
    //n = ATUN_AGAIN;
    //} else {
    // unrecoverable error
    //    break;
    //}

    //} while (errno == EINTR);

    atun_finalize_conn(uc);

    return ATUN_ERROR;

#if (0)
    int n = recv(uc->fd, buf + PROTO_SIZE, DATA_SIZE - PROTO_SIZE, 0);
    if (n <= 0) {
        if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
            return 0;
        }

        std::cout <<  __func__ << " fatal " << errno << "\n";

        atun_select_del_event(uc->read_event, ATUN_READ_EVENT, 0);
        atun_free_connection(uc);

        return -1;
    }
#endif

}

atun_int_t atun_handle_upstream_write(atun_event_t *ev)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);

    if (chains_map[c->suid].empty()) {

        return ATUN_OK;
    }

    ssize_t all_size = 0;

    for (auto it = chains_map[c->suid].begin(); it != chains_map[c->suid].end(); ++it) {
        all_size += it->second;
    }

    u_char *all = (u_char *)atun_alloc(all_size), *osave = all;
    for (auto it = chains_map[c->suid].begin(); it != chains_map[c->suid].end(); ++it) {
        memcpy(all, it->first, it->second);
        all += it->second;
        atun_alloc_free(it->first);
    }

    all = osave;
    chains_map[c->suid].clear();

    //for ( ;; ) {

    ssize_t n = send(c->fd, all, all_size, 0);
    if (n > 0) {

        std::cout << "up write " << all_size << " -->> " << n << "\n";

        //all += n;
        //all_size -= n;

        ssize_t left = all_size - n;

        if (left == 0) {

            atun_del_event(c->write_event, ATUN_WRITE_EVENT, 0);

            atun_alloc_free(all);

            return ATUN_OK;
        }

        u_char *remain = (u_char *)atun_alloc(left);
        memcpy(remain, all + n, left);
        chains_map[c->suid].push_front(std::make_pair(remain, left));

        atun_alloc_free(all);

        return ATUN_OK;
    }

    if (errno == EINTR || errno == EAGAIN) {

        std::cout << "send retry...." << c << "\n";

        size_t left = all_size;
        chains_map[c->suid].push_front(std::make_pair(all, left));

        if (c->eof) {
            std::cout << "broken connection...." << c << "\n";
            return ATUN_OK;
        }

        if (!c->write_event->active) {
            c->write_event->handler = atun_handle_upstream_write;
            c->write_event->write = 1;
            atun_add_event(c->write_event, ATUN_WRITE_EVENT, 0);
        }

        return ATUN_AGAIN;
    }

    // unrecoverable
    atun_finalize_conn(c);

    return ATUN_ERROR;

    //}

#if (0)
    int n = send(c->fd, item.first, item.second, 0);

    if (n == 0) {
        return n;
    }

    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            uplnks[c->suid].push_front(item);
            //uplnks[c->suid] = up_queue;
            return 0;
        }

        uplnks[c->suid].push_front(item);
        // todo fatal error
        std::cout <<  __func__ << " send fatal " << strerror(errno) << "\n";
        return -1;
    }

    item.second -= n;
    item.first += n;

    if (item.second == 0) {
        return 0;
        //delete [] opos;
    }

    uplnks[c->suid].push_front(std::make_pair(opos, item.second));
#endif

}
