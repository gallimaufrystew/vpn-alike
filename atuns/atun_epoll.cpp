
#include "atun_epoll.h"
#include "atun_mem.h"

static int                  ep = -1;
static struct epoll_event  *event_list;
static atun_uint_t          nevents;

atun_event_action_t epoll_action = {
    atun_epoll_add_event,
    atun_epoll_del_event,
    atun_epoll_del_connection,
    atun_epoll_process_events,
    atun_epoll_init,
    atun_epoll_done
};

atun_int_t
atun_epoll_init()
{
    if (ep == -1) {
        // from man page: Since Linux 2.6.8,
        // the size argument is ignored,
        // but must be greater than zero;
        ep = epoll_create(1);
        if (ep == -1) {
            return ATUN_ERROR;
        }
    }

    //if (nevents < epcf->events) {
    //    if (event_list) {
    //        atun_free(event_list);
    //    }

    ssize_t event_size = sizeof(struct epoll_event) * ATUN_EVENT_NUMS;

    event_list = static_cast<epoll_event *>(atun_alloc(event_size));
    if (event_list == nullptr) {
        return ATUN_ERROR;
    }
    //}

    nevents = ATUN_EVENT_NUMS;

    return ATUN_OK;
}


void atun_epoll_done()
{
    if (close(ep) == -1) {
        // what...
    }
    ep = -1;

    atun_alloc_free(event_list);

    event_list = nullptr;
    nevents = 0;
}

atun_int_t
atun_epoll_add_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    atun_event_t         *e;
    atun_conn_t    *c;
    struct epoll_event   ee;

    c = static_cast<atun_conn_t *>(ev->data);

    events = (uint32_t) event;

    if (event == ATUN_READ_EVENT) {

        e = c->write_event;
        prev = EPOLLOUT;

#if (ATUN_READ_EVENT != EPOLLIN | EPOLLRDHUP)
        events = EPOLLIN | EPOLLRDHUP;
#endif

    } else {

        e = c->read_event;
        prev = EPOLLIN | EPOLLRDHUP;

#if (ATUN_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;
    } else {
        op = EPOLL_CTL_ADD;
    }

#if (HAVE_EPOLLEXCLUSIVE && HAVE_EPOLLRDHUP)
    if (flags & EXCLUSIVE_EVENT) {
        events &= ~EPOLLRDHUP;
    }
#endif

    ee.events = events | (uint32_t) flags;
    ee.data.ptr = (void *)((uintptr_t) c | ev->instance);

    //atun_log_debug3(LOG_DEBUG_EVENT, ev->log, 0,
    //               "epoll add event: fd:%d op:%d ev:%08XD",
    //               c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        //atun_log_error(LOG_ALERT, ev->log, atun_errno,
        //              "epoll_ctl(%d, %d) failed", op, c->fd);
        return ATUN_ERROR;
    }

    ev->active = 1;

#if 0
    ev->oneshot = (flags & ONESHOT_EVENT) ? 1 : 0;
#endif

    return ATUN_OK;
}

atun_int_t
atun_epoll_del_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    atun_event_t         *e;
    atun_conn_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & ATUN_CLOSE_EVENT) {
        ev->active = 0;
        return ATUN_OK;
    }

    c = static_cast<atun_conn_t *>(ev->data);

    if (event == ATUN_READ_EVENT) {
        e = c->write_event;
        prev = EPOLLOUT;
    } else {
        e = c->read_event;
        prev = EPOLLIN | EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *)((uintptr_t) c | ev->instance);
    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = nullptr;
    }

    //atun_log_debug3(LOG_DEBUG_EVENT, ev->log, 0,
    //               "epoll del event: fd:%d op:%d ev:%08XD",
    //               c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {

        std::cout << "what del event fail...." << "\n";
        //atun_log_error(LOG_ALERT, ev->log, atun_errno,
        //              "epoll_ctl(%d, %d) failed", op, c->fd);
        return ATUN_ERROR;
    }

    ev->active = 0;

    return ATUN_OK;
}

#if (0)
static atun_int_t
atun_epoll_add_connection(atun_conn_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
    ee.data.ptr = (void *)((uintptr_t) c | c->read->instance);

    atun_log_debug2(LOG_DEBUG_EVENT, c->log, 0,
                    "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        atun_log_error(LOG_ALERT, c->log, atun_errno,
                       "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return OK;
}
#endif

atun_int_t
atun_epoll_del_connection(atun_conn_t *c, atun_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

#if (0)
    if (flags & CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return OK;
    }
#endif

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = nullptr;

    std::cout << "del connection..." << "\n";

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        //fatal...
        return ATUN_ERROR;
    }

    c->read_event->active = 0;
    c->write_event->active = 0;

    return ATUN_OK;
}

atun_int_t
atun_epoll_process_events(atun_uint_t timer)
{
    int                events;
    uint32_t           revents;
    atun_int_t          instance, i;
    atun_uint_t         level;
    atun_err_t          err;
    atun_event_t       *rev, *wev;
    //atun_queue_t       *queue;
    atun_conn_t  *c;

    /* TIMER_INFINITE == INFTIM */

    //atun_log_debug1(LOG_DEBUG_EVENT, cycle->log, 0,
    //               "epoll timer: %M", timer);

    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? atun_errno : 0;

    //if (flags & UPDATE_TIME || atun_event_timer_alarm) {
    //    atun_time_update();
    //}

    if (err) {
        if (err == EINTR) {

            //if (atun_event_timer_alarm) {
            //    atun_event_timer_alarm = 0;
            //    return OK;
            //}

            //level = LOG_INFO;

        } else {
            //level = LOG_ALERT;
        }

        //atun_log_error(level, cycle->log, err, "epoll_wait() failed");
        return ATUN_ERROR;
    }

    if (events == 0) {
        if (timer != ATUN_TIMER_INFINITE) {
            return ATUN_OK;
        }

        //atun_log_error(LOG_ALERT, cycle->log, 0,
        //              "epoll_wait() returned no events without timeout");
        return ATUN_ERROR;
    }

    for (i = 0; i < events; i++) {

        c = static_cast<atun_conn_t *>(event_list[i].data.ptr);

        instance = (uintptr_t) c & 1;
        c = (atun_conn_t *)((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read_event;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            //atun_log_debug1(LOG_DEBUG_EVENT, cycle->log, 0,
            //               "epoll: stale event %p", c);
            continue;
        }

        revents = event_list[i].events;

        //atun_log_debug3(LOG_DEBUG_EVENT, cycle->log, 0,
        //               "epoll: fd:%d ev:%04XD d:%p",
        //               c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR | EPOLLHUP)) {
            //atun_log_debug2(LOG_DEBUG_EVENT, cycle->log, 0,
            //               "epoll_wait() error on fd:%d ev:%04XD",
            //              c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN | EPOLLOUT;
        }

#if 0
        if (revents & ~(EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP)) {
            atun_log_error(LOG_ALERT, cycle->log, 0,
                           "strange epoll_wait() events fd:%d ev:%04XD",
                           c->fd, revents);
        }
#endif

        if ((revents & EPOLLIN) && rev->active) {

#if (HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }

            rev->available = 1;
#endif

            rev->ready = 1;

            //if (flags & ATUN_POST_EVENTS) {
            //    queue = rev->accept ? &atun_posted_accept_events
            //                        : &atun_posted_events;

            atun_post_event(rev);

            //} else {
            //    rev->handler(rev);
            //}
        }

        wev = c->write_event;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                //atun_log_debug1(LOG_DEBUG_EVENT, cycle->log, 0,
                //               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;

#if (ATUN_THREADS)
            wev->complete = 1;
#endif

            //if (flags & POST_EVENTS) {
            atun_post_event(wev);

            //} else {
            //    wev->handler(wev);
            //}
        }
    }

    return ATUN_OK;
}
