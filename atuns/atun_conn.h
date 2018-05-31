
/*
 * File:   atun_conn.h
 * Author: 19020107
 *
 * Created on May 10, 2018, 3:57 PM
 */

#ifndef ATUN_CONN_H_INCLUDED
#define ATUN_CONN_H_INCLUDED

#include "atun_event.h"
#include "atun_mem.h"

typedef std::list<atun_conn_t *> atun_conn_list;

void atun_conn_init(atun_int_t max_conns = ATUN_MAX_CONNECTIONS);
atun_conn_t *atun_retrieve_conn();
atun_int_t atun_handle_event_accept(atun_event_t *ev);
atun_int_t atun_handle_upstream_read(atun_event_t *ev);
atun_int_t atun_handle_upstream_write(atun_event_t *ev);
atun_int_t atun_add_accept_event(atun_sock_t ls);
void atun_free_conn(atun_conn_t *c);
void atun_free_all_conns();
void atun_free_ssl_conn();

#endif
