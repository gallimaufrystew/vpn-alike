
/*
 * File:   atun_event.h
 * Author: 19020107
 *
 * Created on April 29, 2018, 4:25 PM
 */

#ifndef ATUN_EVENT_H
#define ATUN_EVENT_H

#include "atun_sys.h"
#include "atun_socket.h"

#define ATUN_INVALID_INDEX   0xd0d0d0d0
#define ATUN_TIMER_INFINITE  (atun_int_t) -1

// configurable?
#define ATUN_MAX_CONNECTIONS  32

#if (USE_EPOLL)

    #define ATUN_CLOSE_EVENT     1
    #define ATUN_READ_EVENT      (EPOLLIN | EPOLLRDHUP)
    #define ATUN_WRITE_EVENT     EPOLLOUT

#elif (USE_KQUEUE)

    // not implemented....

#elif (USE_EVENT_PORT)

    // not implemented....

#elif (USE_IOCP)

    // not implemented....

#else // select is the last resort

    #define ATUN_READ_EVENT     0
    #define ATUN_WRITE_EVENT    1

#endif

typedef struct atun_event_s atun_event_t;
typedef struct atun_conn_s atun_conn_t;

typedef atun_int_t (*atun_event_handler)(atun_event_t *ev);

typedef std::queue<atun_event_t *> atun_event_queue_t;
typedef atun_int_t atun_blk_size;
typedef atun_int_t atun_conn_id;
typedef std::pair<u_char *, atun_blk_size> atun_blk_t;
typedef std::list<atun_blk_t> atun_chain_t;
typedef std::unordered_map<atun_conn_id, atun_chain_t> atun_chain_map_t;
typedef std::pair<atun_conn_t *, time_t> atun_conn_time_t;
typedef std::unordered_map<atun_conn_id, atun_conn_time_t> atun_conn_map_t;

typedef struct {

    atun_int_t (*add)(atun_event_t *ev, atun_uint_t event, atun_uint_t flags);
    atun_int_t (*del)(atun_event_t *ev, atun_uint_t event, atun_uint_t flags);

#if (0)
    atun_int_t (*enable)(atun_event_t *ev, atun_int_t event, atun_uint_t flags);
    atun_int_t (*disable)(atun_event_t *ev, atun_int_t event, atun_uint_t flags);
    atun_int_t (*add_conn)(atun_conn_t *c);
#endif

    atun_int_t (*del_conn)(atun_conn_t *c, atun_uint_t flags);

#if (0)
    atun_int_t (*notify)(atun_event_handler_pt handler);
#endif

    atun_int_t (*process_events)(atun_uint_t timer);

    atun_int_t (*init)();
    void (*done)();

} atun_event_action_t;

extern atun_event_action_t   atun_event_action;

struct atun_conn_s {
    atun_sock_t          fd;
    atun_event_t        *read_event;
    atun_event_t        *write_event;
    atun_int_t           suid;//, port;
    unsigned             eof;
    atun_conn_t         *peer;
};

struct atun_event_s {
    void               *data;
    unsigned            write: 1;
    unsigned            accept: 1;
    unsigned            active: 1;
    unsigned            ready: 1;
    unsigned            instance: 1;
    atun_uint_t         index;
    atun_event_handler  handler;
};

#define atun_process_events   atun_event_action.process_events
#define atun_done_events      atun_event_action.done

#define atun_add_event        atun_event_action.add
#define atun_del_event        atun_event_action.del
#if (0)
    #define atun_add_conn         atun_event_action.add_conn
#endif
#define atun_del_conn         atun_event_action.del_conn

void atun_process_posted_event();
void atun_post_event(atun_event_t *ev);
void atun_cleanup_event_queue();
void atun_event_process_init();
void atun_check_timeout();
void atun_cleanup_one_upconn(atun_conn_t *uc);

#endif /* ATUN_EVENT_H */
