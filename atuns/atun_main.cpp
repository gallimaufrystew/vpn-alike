/*
 * File:   atun_main.cpp
 * Author: 19020107
 *
 * Created on May 03, 2018, 4:34 PM
 */

#include "atun_main.h"
#include "atun_signal.h"
#include "atun_config.h"
#include "atun_socket.h"
#include "atun_mem.h"
#include "atun_conn.h"
#include "atun_ssl.h"

extern sig_atomic_t sig_exit;
extern atun_int_t atun_daemon();

int main(int argc, char *argv[])
{
    /* start watcher and workers */
    atun_int_t num_childs = 1;

    //pid_t pids[num_childs];

    pid_t pid;

    //const int npids = num_childs;

    atun_int_t child = 0;

    //unsigned int timer = 0;
    //for (int n = 0; n < npids; ++n) pids[n] = -1;

    std::cout << ATUN_VER_BUILD << ATUN_LINEFEED;

    atun_daemon();

    while (!child && !sig_exit) {

        if (num_childs > 0) {

            switch ((pid = fork())) {
            case -1:
                return -1;
            case 0:
                child = 1;
                //alarm(0);
                break;
            default:
                num_childs--;
                //for (int n = 0; n < npids; ++n) {
                //  if (-1 == pids[n]) {
                //      pids[n] = pid;
                //      break;
                //  }
                //}
                break;
            }
        } else {

            int status;

            if (-1 != (pid = wait(&status))) {
                //srv->cur_ts = time(NULL);
                //if (plugins_call_handle_waitpid(srv, pid, status) != HANDLER_GO_ON) {
                //  if (!timer) alarm((timer = 5));
                //  continue;
                //}
                //switch (fdevent_reaped_logger_pipe(pid)) {
                //  default: break;
                //  case -1: if (!timer) alarm((timer = 5));
                //     /* fall through */
                //  case  1: continue;
                //}
                /**
                 * check if one of our workers went away
                 */
                //for (int n = 0; n < npids; ++n) {
                //  if (pid == pids[n]) {
                //      pids[n] = -1;

                num_childs++;

                break;
                //  }
            } else {
                switch (errno) {
                case EINTR:
                    //srv->cur_ts = time(NULL);
                    /**
                     * if we receive a SIGHUP we have to close our logs ourself as we don't
                     * have the mainloop who can help us here
                     */
                    if (0) {
                        //handle_sig_hup = 0;

                        //log_error_cycle(srv);

                        /* forward SIGHUP to workers */
                        //for (int n = 0; n < npids; ++n) {
                        //  if (pids[n] > 0) kill(pids[n], SIGHUP);
                        //}
                    }
                    if (0) {
                        //handle_sig_alarm = 0;
                        //timer = 0;
                        //plugins_call_handle_trigger(srv);
                        //fdevent_restart_logger_pipes(srv->cur_ts);
                    }
                    break;
                default:
                    break;
                }
            }
        }
    }

    /**
     * for the parent this is the exit-point
     */
    if (!child) {

        kill(0, SIGINT);

#if (0)
        /**
         * kill all children too
         */
        if (1) {
            //graceful_shutdown || graceful_restart
            /* flag to ignore one SIGINT if graceful_restart */
            //if (graceful_restart) graceful_restart = 2;
            kill(0, SIGINT);
            //server_graceful_state(srv);
        } else if (0) {//srv_shutdown
            kill(0, SIGTERM);
        }
#endif
        return 0;
    }

    atun_config_init();

    atun_signal_init();

    atun_event_process_init();

    atun_conn_init();

    int sock = atun_listen_init();
    if (sock <= 0) {
        std::cout << "init_listen_socket..." << "\n";
        return -1;
    }

    atun_add_accept_event(sock);

    atun_ssl_init();

    std::cout << "start handling event..." << "\n";

    for (;;) {

        if (sig_exit) {
            break;
        }

        atun_process_events(1000);

        atun_process_posted_event();

        atun_check_timeout();
    }

    /* cleanup */

    return 0;
}
