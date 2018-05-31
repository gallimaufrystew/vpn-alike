
#include "atun_event.h"
#include "atun_conn.h"
#include "atun_ssl.h"

atun_event_action_t atun_event_action;

extern atun_event_action_t select_action;
extern atun_event_action_t epoll_action;

static atun_event_queue_t  posted_events;

extern atun_chain_map_t chains_map;
extern atun_conn_map_t conns_map;
extern atun_chain_t ssl_send_chain, ssl_recv_chain;

void atun_event_process_init()
{

#if (USE_EPOLL)

    atun_event_action = epoll_action;

#elif (USE_KQUEUE)
    ///////////////////////////////////////
#elif (USE_EVENT_PORT)
    ///////////////////////////////////////
#else
    atun_event_action = select_action;
#endif

    atun_event_action.init();
}

void atun_cleanup_one_upstream(atun_conn_t *uc)
{
    std::cout << "cleanup...." << "\n";

    atun_del_conn(uc, 0);
    atun_cleanup_one(chains_map[uc->suid]);
    chains_map.erase(uc->suid);
    conns_map.erase(uc->suid);
    atun_close_sock(uc->fd);
#if (1)
    atun_free_conn(uc);
#endif
}

void atun_process_posted_event()
{
    std::unordered_set<atun_conn_t *> conns;

    while (!posted_events.empty()) {

        atun_event_t *ev = posted_events.front();

        posted_events.pop();

        atun_conn_t *c = (atun_conn_t *)ev->data;

        // non-active connection
        if (c->eof) {
            conns.insert(c);
            continue;
        }

        ev->handler(ev);
    }

    // cleanup up connection
    for (auto it = conns.begin(); it != conns.end(); ++it) {
        atun_cleanup_one_upstream(*it);
    }
}

void atun_post_event(atun_event_t *ev)
{
    posted_events.push(ev);
}

void atun_cleanup_event_queue()
{
    std::queue<atun_event_t *> empty;
    std::swap(posted_events, empty);
}

void atun_check_timeout()
{
    time_t current = time(NULL);

    // over 20 seconds have elapsed with no activity
    for (auto it = conns_map.begin(); it != conns_map.end(); ++it) {
        auto uc = it->second;
        if (difftime(current, uc.second) >= 30) {
            //std::cout << "timeout...." << "\n";
            uc.first->eof = 1;
            //atun_cleanup_one_upconn(uc.first);
        }
    }

    //debug_check();
}
