
/*
 * File:   atun_epoll.h
 * Author: 19020107
 *
 * Created on May 10, 2018, 3:57 PM
 */

#ifndef ATUN_EPOLL_H
#define ATUN_EPOLL_H

#include "atun_err.h"
#include "atun_sys.h"
#include "atun_event.h"
#include "atun_socket.h"

#define ATUN_EVENT_NUMS 32

atun_int_t atun_epoll_init();
atun_int_t atun_epoll_add_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags);
atun_int_t atun_epoll_del_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags);
atun_int_t atun_epoll_process_events(atun_uint_t timer);
atun_int_t atun_epoll_del_connection(atun_conn_t *c, atun_uint_t flags);
void atun_epoll_done();

#endif /* ATUN_EPOLL_H */

