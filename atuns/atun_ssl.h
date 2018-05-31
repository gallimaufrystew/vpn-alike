
/*
 * File:   atun_ssl.h
 * Author: 19020107
 *
 * Created on April 29, 2018, 5:57 PM
 */

#ifndef ATUN_SSL_H_INCLUDED
#define ATUN_SSL_H_INCLUDED

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "atun_event.h"
#include "atun_mem.h"
#include "atun_config.h"
#include "atun_conn.h"

#define ATUN_SSL_CUST_EXT_TYPE_100 10000

#define ATUN_PROTO_SIZE   12
#define ATUN_DATA_SIZE    16 * 1024

typedef struct {
    bool           verify_peer;
    bool           connected;
    atun_int_t     fd;
    SSL           *ssl;
    SSL_CTX       *old_ctx;
    SSL_CTX       *new_ctx;
} ssl_session_t;

void atun_ssl_init();
atun_int_t atun_ssl_session_init(atun_int_t fd);
atun_int_t atun_handle_ssl_handshake(atun_event_t *ev);
atun_int_t atun_handle_ssl_write(atun_event_t *ev);
atun_int_t atun_upstream_init(atun_conn_t *c, atun_int_t fd, atun_int_t suid);
void atun_cleanup_one(atun_chain_t &one);

#endif /* ATUN_SSL_H_INCLUDED */
