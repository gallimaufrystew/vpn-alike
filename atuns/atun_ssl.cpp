
#include "atun_ssl.h"

static atun_int_t atun_handle_ssl_verify(atun_event_t *ev);

static atun_int_t atun_connect_backend(atun_event_t *ev, atun_int_t suid, atun_int_t port);
static bool atun_conn_exists(atun_int_t suid);

static void atun_ssl_clear_error();
static atun_int_t atun_check_ssl_status(SSL *ssl, ssize_t n);
static void atun_add_upstream_write_event(atun_conn_t *c);
static void atun_cleanup_ssl();
atun_int_t atun_handle_ssl_write(atun_event_t *ev);
atun_int_t atun_handle_ssl_read(atun_event_t *ev);

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in, size_t inlen, int *al, void *arg);
static SSL_CTX *create_context(const char *sign_algo);

static const char *passwd = "123456", *rfb_command = "RFB_OPEN";
static const atun_int_t rfb_listen_port = 5900;

static ssl_session_t *ssl_session;

extern port_map_t port_map;

atun_chain_map_t chains_map;

atun_chain_t ssl_send_chain, ssl_recv_chain;
atun_conn_map_t conns_map;

atun_int_t
atun_handle_ssl_handshake(atun_event_t *ev)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);

    atun_ssl_clear_error();

    SSL_set_fd(ssl_session->ssl, ssl_session->fd);

    atun_int_t n = SSL_do_handshake(ssl_session->ssl);
    if (n <= 0) {
        atun_err_t err = SSL_get_error(ssl_session->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return ATUN_OK;
        }

        ERR_print_errors_fp(stderr);

        atun_cleanup_ssl();

        return ATUN_ERROR;
    }

    ev->handler = atun_handle_ssl_verify;

    return ATUN_OK;
}

atun_int_t
atun_verify_peer()
{
    if (!ssl_session->verify_peer) {
        return ATUN_OK;
    }

    X509 *cert = SSL_get_peer_certificate(ssl_session->ssl);
    if (!cert) {
        std::cout << "no peer certificate" << "\n";
        return ATUN_ERROR;
    }

    long ret = SSL_get_verify_result(ssl_session->ssl);
    if (ret != X509_V_OK) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return ATUN_ERROR;
    }

    X509_free(cert);

    return ATUN_OK;
}

static atun_int_t
atun_handle_ssl_verify(atun_event_t *ev)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);

    atun_int_t ret = atun_verify_peer();
    if (ret != 0) {
        atun_cleanup_ssl();
    }

    ev->handler = atun_handle_ssl_read;

    return ATUN_OK;
}

static void
atun_ssl_clear_error()
{
#if (0)
    while (ERR_peek_error()) {
    }
#endif
    ERR_clear_error();
}

static ssize_t
atun_ssl_read(u_char *buf, size_t size)
{
    ssize_t  n, bytes;

    bytes = 0;

    atun_ssl_clear_error();

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for (;;) {

        n = SSL_read(ssl_session->ssl, buf, size);
        if (n > 0) {
            bytes += n;
        }

        int ret = atun_check_ssl_status(ssl_session->ssl, n);
        if (ret == ATUN_OK) {

            size -= n;

            if (size == 0) {
                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            return bytes;
        }

        switch (ret) {
        case ATUN_DONE:
        case ATUN_ERROR:
            return ATUN_ERROR;
        case ATUN_AGAIN:
            return ATUN_AGAIN;
        }
    }
}

static atun_int_t
atun_ana_proto(atun_conn_t *c, atun_event_t *ev,
               u_char *ssl_buf, size_t all_size)
{
    ssize_t  consumed = 0;

bleed_next_:

    if (all_size <= ATUN_PROTO_SIZE) {
        return consumed;
    }

    int32_t len, nlen;
    memcpy(&nlen, ssl_buf, 4);
    len = ntohl(nlen);

    int32_t  port, nport;
    memcpy(&nport, ssl_buf + 4, 4);
    port = ntohl(nport);

    int32_t  suid, nsuid;
    memcpy(&nsuid, ssl_buf + 8, 4);
    suid = ntohl(nsuid);

    if (all_size - ATUN_PROTO_SIZE < len) {
        return consumed;
    }

    if (!atun_conn_exists(suid)) {

        int sock = atun_connect_backend(ev, suid, port);
        if (sock <= 0) {

            // skip

            consumed += (ATUN_PROTO_SIZE + len);
            ssl_buf  += (ATUN_PROTO_SIZE + len);
            all_size -= (ATUN_PROTO_SIZE + len);

            goto bleed_next_;

            //return ATUN_ERROR;
        }

        atun_upstream_init(c, sock, suid);

        atun_chain_t nil;
        chains_map[suid] = nil;

        auto host = port_map[port];

        if (host.second == rfb_listen_port) {

            consumed += (ATUN_PROTO_SIZE + len);
            ssl_buf  += (ATUN_PROTO_SIZE + len);
            all_size -= (ATUN_PROTO_SIZE + len);

            goto bleed_next_;
        }
    }

#if (1)

    // update last active time
    auto uc = conns_map[suid].first;
    conns_map[suid] = std::make_pair(uc, time(NULL));

    // still alive?

    //std::cout << "up...........uid..." << suid << "\n";

    if (!uc->eof) {

        u_char *up_data = (u_char *)atun_alloc(len);
        std::memcpy(up_data, ssl_buf + ATUN_PROTO_SIZE, len);

        //std::cout << "up...........uid..." << suid << "\n";
        size_t up_size = len;
        chains_map[suid].push_back(std::make_pair(up_data, up_size));

        atun_add_upstream_write_event(uc);
    }

#endif

    consumed += (ATUN_PROTO_SIZE + len);
    ssl_buf  += (ATUN_PROTO_SIZE + len);
    all_size -= (ATUN_PROTO_SIZE + len);

    goto bleed_next_;
}

static void
atun_add_upstream_write_event(atun_conn_t *c)
{
#if (0)
    atun_conn_t *uc = c->peer;
    if (uc == nullptr) {
        std::cout << "atun_add_upstream_write_event what ... " << "\n";
        return;
    }
#endif

    if (c->eof) {
        std::cout << "broken connection...." << c << "\n";
        return;
    }

    if (!c->write_event->active) {
        c->write_event->handler = atun_handle_upstream_write;
        c->write_event->write = 1;
        atun_add_event(c->write_event, ATUN_WRITE_EVENT, 0);
    }
}

ssize_t atun_cal_size(ssize_t n)
{
    ssize_t left_size = 0;
    for (auto it = ssl_recv_chain.begin(); it != ssl_recv_chain.end(); ++it) {
        left_size += it->second;
    }
    return left_size + n;
}

atun_int_t atun_save_ssl_buf(u_char *ssl_buf, ssize_t n)
{
    u_char *save = static_cast<u_char *>(atun_alloc(n));
    memcpy(save, ssl_buf, n);
    ssl_recv_chain.push_back(std::make_pair(save, n));
}

void atun_coalesce_buf(u_char *all, u_char *last, ssize_t n)
{
    for (auto it = ssl_recv_chain.begin(); it != ssl_recv_chain.end(); ++it) {
        memcpy(all, it->first, it->second);
        all += it->second;
        atun_alloc_free(it->first);
    }
    memcpy(all, last, n);
}

atun_int_t
atun_handle_ssl_read(atun_event_t *ev)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);

#define SSL_SIZE 8192

    u_char ssl_buf[SSL_SIZE] = {};
    ssize_t size = SSL_SIZE;

    ssize_t n = atun_ssl_read(ssl_buf, size);

    //std::cout << "atun_ssl_read -> " << n << "\n";

    if (n <= 0) {
        if (n == ATUN_AGAIN) {
            return ATUN_OK;
        }
        atun_cleanup_ssl();
        return ATUN_ERROR;
    }

#if (0)
    u_char *save = static_cast<u_char *>(atun_alloc(n));
    memcpy(save, ssl_buf, n);
    ssl_recv_chain.push_back(std::make_pair(save, n));
#endif

#if (1)

    ssize_t all_size = atun_cal_size(n);
    if (all_size <= ATUN_PROTO_SIZE) {
        atun_save_ssl_buf(ssl_buf, n);
        return ATUN_OK;
    }

    u_char *all = (u_char *)atun_alloc(all_size), *osave = all;

    atun_coalesce_buf(all, ssl_buf, n);

    ssl_recv_chain.clear();

    all = osave;

    int consumed = atun_ana_proto(c, ev, all, all_size);
    if (consumed > 0) {

        int left_size = all_size - consumed;

        if (left_size > 0) {
            u_char *left = (u_char *)atun_alloc(left_size);
            memcpy(left, all + consumed, left_size);
            ssl_recv_chain.push_front(std::make_pair(left, left_size));
        }

        atun_alloc_free(all);

        return ATUN_OK;
    }

    std::cout << "why....." << "\n";

    ssl_recv_chain.push_front(std::make_pair(all, all_size));

    return ATUN_OK;

#endif

}

static bool
atun_conn_exists(atun_int_t suid)
{
    auto it = chains_map.find(suid);
    if (it == chains_map.end()) {
        return false;
    }
    return true;
}

static atun_int_t
atun_check_ssl_status(SSL *ssl, atun_int_t n)
{
    int         sslerr;
    atun_err_t  err;

    if (n > 0) {
        return ATUN_OK;
    }

    sslerr = SSL_get_error(ssl, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? atun_errno : 0;

    if (sslerr == SSL_ERROR_WANT_READ) {
        return ATUN_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        //std::printf("peer started SSL renegotiation");
        return ATUN_AGAIN;
    }

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        std::printf("ssl return zero\n");
        return ATUN_DONE;
    }

    std::printf("SSL_read() err\n");

    return ATUN_ERROR;
}

atun_int_t atun_handle_ssl_write(atun_event_t *ev)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);

    if (ssl_send_chain.empty()) {
        return ATUN_OK;
    }

    ssize_t all_size = 0;

    for (auto it = ssl_send_chain.begin(); it != ssl_send_chain.end(); ++it) {
        all_size += it->second;
    }

    u_char *all = (u_char *)atun_alloc(all_size), *save = all;
    for (auto it = ssl_send_chain.begin(); it != ssl_send_chain.end(); ++it) {
        memcpy(all, it->first, it->second);
        all += it->second;
        atun_alloc_free(it->first);
    }

    ssl_send_chain.clear();

    all = save;

    std::cout << "ssl write all_size <<<<  " << all_size << "\n";

    /// retry with exact the same parameters
    //retry__:

    atun_ssl_clear_error();

    auto n = SSL_write(ssl_session->ssl, all, all_size);

    std::cout << "ssl write <<<<<<<<<<<<  " << n << "\n";

    if (n > 0) {

        if (n == all_size) {
            atun_del_event(c->write_event, ATUN_WRITE_EVENT, 0);
            atun_alloc_free(all);
            return ATUN_OK;
        }

        int left_size = all_size - n;
        u_char *left = (u_char *)atun_alloc(left_size);
        memcpy(left, all + n, left_size);

        ssl_send_chain.push_front(std::make_pair(left, left_size));

        atun_alloc_free(all);

        return ATUN_OK;
    }

    /*

    #define SSL_ERROR_NONE               0
    #define SSL_ERROR_SSL                1
    #define SSL_ERROR_WANT_READ          2
    #define SSL_ERROR_WANT_WRITE         3
    #define SSL_ERROR_WANT_X509_LOOKUP   4
    #define SSL_ERROR_SYSCALL            5
    #define SSL_ERROR_ZERO_RETURN        6
    #define SSL_ERROR_WANT_CONNECT       7
    #define SSL_ERROR_WANT_ACCEPT        8

    */

    ERR_print_errors_fp(stderr);

    int sslerr = SSL_get_error(ssl_session->ssl, n);

    int err = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;

    // retry
    if (sslerr == SSL_ERROR_WANT_WRITE || sslerr == SSL_ERROR_WANT_READ) {

        std::cout << "recoverable..retry.." << "\n";

        //goto retry__;

        //atun_add_event(c->write_event, ATUN_WRITE_EVENT, 0);

        //ssl_send_chain.push_front(std::make_pair(all, all_size));

        return ATUN_AGAIN;
    }

    std::cout << "SSL_write unrecoverable... " << sslerr << "\n";

    // unrecoverable
    atun_cleanup_ssl();

    return ATUN_ERROR;
}

atun_int_t atun_upstream_init(atun_conn_t *c, atun_int_t fd, atun_int_t suid)
{
    atun_conn_t *uc = atun_retrieve_conn();
    if (uc == nullptr) {
        // fatal...
        return ATUN_ERROR;
    }

    atun_set_nonblock(fd);

    uc->fd = fd;
    atun_event_t *rev = uc->read_event;

    uc->suid = suid;
    uc->peer = c;

    rev->index = ATUN_INVALID_INDEX;
    rev->write = 0;
    rev->handler = atun_handle_upstream_read;

    atun_add_event(rev, ATUN_READ_EVENT, 0);

#if (0)
    atun_event_t *wev = uc->write_event;
    wev->index = ATUN_INVALID_INDEX;
    wev->write = 1;
    wev->handler = atun_upstream_write;

    atun_select_add_event(wev, ATUN_WRITE_EVENT, 0);
#endif

    // record the initial time
    conns_map[uc->suid] = std::make_pair(uc, time(NULL));

    return ATUN_OK;
}

atun_int_t atun_connect_backend(atun_event_t *ev, atun_int_t suid, atun_int_t port)
{
    atun_conn_t *c = static_cast<atun_conn_t *>(ev->data);

    auto host = port_map[port];

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(host.second);

    //std::cout << "backend.... " << host.first << "\n";

    if (valid_ip(host.first, addr)) {

        //std::cout << "connect by ip...\n";

        atun_sock_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            // possible?
            return ATUN_ERROR;
        }

        atun_set_nonblock(sock);

        atun_int_t ret = async_connect(sock, (sockaddr *)&addr, sizeof(addr));
        if (ret <= 0) {
            atun_close_sock(sock);
            return ATUN_ERROR;
        }

        //std::cout << "up fd " << sock << "\n";

        return sock;
    }

    //std::cout << "connect by hostname..." << "\n";

    atun_sock_t sock = async_connect_by_hostname(host.first, host.second);
    if (sock <= 0) {
        std::cout << "async_connect_upstream fail" << "\n";
        return ATUN_ERROR;
    }

    return sock;
}


void atun_ssl_init()
{
    SSL_library_init();
    SSL_load_error_strings();
}

void atun_free_ssl()
{
    SSL_shutdown(ssl_session->ssl);
    SSL_CTX_free(ssl_session->old_ctx);
    SSL_CTX_free(ssl_session->new_ctx);
    SSL_free(ssl_session->ssl);
}

void atun_cleanup_one(atun_chain_t &one)
{
    for (auto it = one.begin(); it != one.end(); ++it) {
        atun_alloc_free(it->first);
    }
    one.clear();
}

void atun_cleanup_queue()
{
    for (auto it = chains_map.begin(); it != chains_map.end(); ++it) {
        atun_cleanup_one(it->second);
    }
    chains_map.clear();
}

void atun_del_all_event()
{
    for (auto it = conns_map.begin(); it != conns_map.end(); ++it) {
        atun_del_conn(it->second.first, 0);
        atun_close_sock(it->second.first->fd);
    }
    conns_map.clear();
}

void atun_cleanup_ssl()
{
    // clear all events
    atun_del_all_event();

    // cleanup all buffered data
    atun_cleanup_queue();

    // clear all posted event
    atun_cleanup_event_queue();

    // cleanup ssl library structure
    atun_free_ssl();

    // reclaim all connections
    atun_free_all_conns();

    atun_free_ssl_conn();

    atun_close_sock(ssl_session->fd);

    // free my allocation
    atun_alloc_free(ssl_session);
    ssl_session = nullptr;
}

atun_int_t
atun_ssl_session_init(atun_int_t fd)
{
    if (ssl_session) {
        atun_cleanup_ssl();
    }
    auto size = sizeof(ssl_session_t);
    ssl_session = static_cast<ssl_session_t *>(atun_alloc(size));
    if (!ssl_session) {
        // fatal...
        return ATUN_ERROR;
    }
    ssl_session->verify_peer = false;
    ssl_session->fd = fd;
    ssl_session->new_ctx = create_context("sha2");
    ssl_session->old_ctx = create_context("sha2");
    ssl_session->ssl = SSL_new(ssl_session->old_ctx);
    if (!ssl_session->ssl) {
        // fatal...
        return ATUN_ERROR;
    }

    SSL_set_accept_state(ssl_session->ssl);

    return ATUN_OK;
}

static SSL_CTX *create_context(const char *sign_algo)
{
    SSL_CTX *ctx = nullptr;
    char file_name[512] = {0};

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) passwd);
    SSL_CTX_add_server_custom_ext(ctx, ATUN_SSL_CUST_EXT_TYPE_100,
                                  nullptr, nullptr, nullptr, ana_ext_callback, ssl_session);

    std::sprintf(file_name, "server_%s.crt", sign_algo);

#if (1)
    //SSL_CTX_use_certificate_chain_file
    if (SSL_CTX_use_certificate_file(ctx, file_name, SSL_FILETYPE_PEM)
            <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
#else
    X509 *x509 = load_cert(file_name);

    if (SSL_CTX_use_certificate(ssl_ctx, x509) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    X509_free(x509);
#endif

    sprintf(file_name, "server_%s.key", sign_algo);
    if (SSL_CTX_use_PrivateKey_file(ctx, file_name, SSL_FILETYPE_PEM)
            <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

#if (1)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    // we can string certs together to form a cert-chain
    sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ctx, file_name, nullptr)) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    //SSL_CTX_set_verify_depth(ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ctx, svr_name_callback);
#endif

    return ctx;
}

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in, size_t inlen, int *al, void *arg)
{
    char  ext_buf[2048] = {0};
    char *tag = nullptr;
    char  cust_tag[1024] = {0};

    std::memcpy(ext_buf, in, inlen);

    //printf("---ext parse callback---\n");

    tag = strstr(ext_buf, "sign_algo=");
    if (tag) {
        sprintf(cust_tag, "%s", tag + strlen("sign_algo="));
    }

    printf("---cert tag [%s]----\n", cust_tag);

    ssl_session_t *session = (ssl_session_t *) arg;

    SSL_set_SSL_CTX(ssl, session->new_ctx);

    return 1;
}
