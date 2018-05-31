
/*
 * File:   atun_select.h
 * Author: 19020107
 *
 * Created on April 29, 2018, 4:19 PM
 */

#ifndef ATUN_SELECT_H
#define ATUN_SELECT_H

#include "atun_err.h"
#include "atun_sys.h"
#include "atun_event.h"
#include "atun_socket.h"

atun_int_t atun_select_init();
atun_int_t atun_select_add_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags);
atun_int_t atun_select_del_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags);
atun_int_t atun_select_process_events(atun_uint_t timer);
void atun_select_done();

#endif /* ATUN_SELECT_H */
