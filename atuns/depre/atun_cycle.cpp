
#include "atun_cycle.h"
#include "atun_process.h"

atun_uint_t    atun_process;
atun_uint_t    atun_worker;
atun_pid_t     atun_pid;
atun_pid_t     atun_parent;

sig_atomic_t  atun_reap;
sig_atomic_t  atun_sigio;
sig_atomic_t  atun_sigalrm;
sig_atomic_t  atun_terminate;
sig_atomic_t  atun_quit;
sig_atomic_t  atun_debug_quit;
atun_uint_t    atun_exiting;
sig_atomic_t  atun_reconfigure;
sig_atomic_t  atun_reopen;

sig_atomic_t  atun_change_binary;
atun_pid_t     atun_new_binary;
atun_uint_t    atun_inherited;
atun_uint_t    atun_daemonized;

sig_atomic_t  atun_noaccept;
atun_uint_t    atun_noaccepting;
atun_uint_t    atun_restart;

void
atun_master_process_cycle()
{
    char              *title;
    u_char            *p;
    size_t             size;
    atun_int_t          i;
    atun_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    atun_uint_t         live;
    
    atun_msec_t         delay;

#if (0)    
    atun_listening_t   *ls;
    atun_core_conf_t   *ccf;
#endif
    
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, atun_signal_value(ATUN_RECONFIGURE_SIG));
    sigaddset(&set, atun_signal_value(ATUN_REOPEN_SIG));
    sigaddset(&set, atun_signal_value(ATUN_NOACCEPT_SIG));
    sigaddset(&set, atun_signal_value(ATUN_TERMINATE_SIG));
    sigaddset(&set, atun_signal_value(ATUN_SHUTDOWN_SIG));
    sigaddset(&set, atun_signal_value(ATUN_CHANGEBIN_SIG));

    if (sigprocmask(SIG_BLOCK, &set, nullptr) == -1) {
    }

    sigemptyset(&set);

#if (0)
    size = sizeof(master_process);

    for (i = 0; i < atun_argc; i++) {
        size += atun_strlen(atun_argv[i]) + 1;
    }

    title = atun_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = atun_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < atun_argc; i++) {
        *p++ = ' ';
        p = atun_cpystrn(p, (u_char *) atun_argv[i], size);
    }

    atun_setproctitle(title);


    ccf = (atun_core_conf_t *) atun_get_conf(cycle->conf_ctx, atun_core_module);

#endif
    
    atun_start_worker_processes(1, ATUN_PROCESS_RESPAWN);
    //atun_start_cache_manager_processes(cycle, 0);

    //atun_new_binary = 0;
    
    delay = 0;
    
    //sigio = 0;
    
    live = 1;

    for ( ;; ) {
        
        if (delay) {

#if (0)
            if (atun_sigalrm) {
                sigio = 0;
                delay *= 2;
                atun_sigalrm = 0;
            }

            atun_log_debug1(ATUN_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                atun_log_error(ATUN_LOG_ALERT, cycle->log, atun_errno,
                              "setitimer() failed");
            }
#endif
        }


        sigsuspend(&set);

        //atun_time_update();

        if (atun_reap) {
            
            atun_reap = 0;
            
            //atun_log_debug0(ATUN_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            live = atun_reap_children();
        }

        if (!live && (atun_terminate || atun_quit)) {
            atun_master_process_exit();
        }

        if (atun_terminate) {
            
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            //sigio = ccf->worker_processes + 2 /* cache processes */;

            if (delay > 1000) {
                atun_signal_worker_processes(SIGKILL);
            } else {
                atun_signal_worker_processes(atun_signal_value(ATUN_TERMINATE_SIG));
            }

            continue;
        }

        if (atun_quit) {
            
            atun_signal_worker_processes(atun_signal_value(ATUN_SHUTDOWN_SIG));

#if (0)
            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (atun_close_socket(ls[n].fd) == -1) {
                    atun_log_error(ATUN_LOG_EMERG, cycle->log, atun_socket_errno,
                                  atun_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;
#endif
            continue;
        }

        if (atun_reconfigure) {
            
            atun_reconfigure = 0;

#if (0)
            if (atun_new_binary) {
                atun_start_worker_processes(cycle, ccf->worker_processes,
                                           ATUN_PROCESS_RESPAWN);
                atun_start_cache_manager_processes(cycle, 0);
                atun_noaccepting = 0;

                continue;
            }
#endif
            
            //atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            //cycle = atun_init_cycle(cycle);
            //if (cycle == NULL) {
            //    cycle = (atun_cycle_t *) atun_cycle;
            //    continue;
            //}

            //atun_cycle = cycle;
            //ccf = (atun_core_conf_t *) atun_get_conf(cycle->conf_ctx,
            //                                       atun_core_module);
            atun_start_worker_processes(1, ATUN_PROCESS_JUST_RESPAWN);
            //atun_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            atun_msleep(100);

            live = 1;
            atun_signal_worker_processes(atun_signal_value(ATUN_SHUTDOWN_SIG));
        }

        if (atun_restart) {
            atun_restart = 0;
            atun_start_worker_processes(1, ATUN_PROCESS_RESPAWN);
            //atun_start_cache_manager_processes(cycle, 0);
            live = 1;
        }

        if (atun_reopen) {
            //atun_reopen = 0;
            //atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "reopening logs");
            //atun_reopen_files(cycle, ccf->user);
            //atun_signal_worker_processes(cycle,
            //                            atun_signal_value(ATUN_REOPEN_SIGNAL));
        }

        //if (atun_change_binary) {
            //atun_change_binary = 0;
            //atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "changing binary");
            //atun_new_binary = atun_exec_new_binary(cycle, atun_argv);
        //}

        //if (atun_noaccept) {
        //    atun_noaccept = 0;
        //    atun_noaccepting = 1;
        //    atun_signal_worker_processes(cycle,
        //                                atun_signal_value(ATUN_SHUTDOWN_SIGNAL));
        //}
    }
}

static void
atun_start_worker_processes(atun_int_t n, atun_int_t type)
{
    atun_int_t      i;
    //atun_channel_t  ch;

    //atun_memzero(&ch, sizeof(atun_channel_t));

    //ch.command = ATUN_CMD_OPEN_CHANNEL;

    for (i = 0; i < n; i++) {

        atun_spawn_process(atun_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        //ch.pid = atun_processes[atun_process_slot].pid;
        //ch.slot = atun_process_slot;
        //ch.fd = atun_processes[atun_process_slot].channel[0];

        //atun_pass_open_channel(cycle, &ch);
    }
}


static void
atun_worker_process_cycle(void *data)
{
    atun_int_t worker = (intptr_t) data;

    //atun_process = ATUN_PROCESS_WORKER;
    //atun_worker = worker;

    //atun_worker_process_init(cycle, worker);

    //atun_setproctitle("worker process");

    for ( ;; ) {

        if (atun_exiting) {
            //if (atun_event_no_timers_left() == ATUN_OK) {
            //    atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "exiting");
            //    atun_worker_process_exit(cycle);
            //}
        }

        //atun_log_debug0(ATUN_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        //atun_process_events_and_timers(cycle);

        if (atun_terminate) {
            //atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "exiting");
            //atun_worker_process_exit(cycle);
        }

        if (atun_quit) {
            //atun_quit = 0;
            //atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0,
            //              "gracefully shutting down");
            //atun_setproctitle("worker process is shutting down");

            //if (!atun_exiting) {
            //    atun_exiting = 1;
            //    atun_set_shutdown_timer(cycle);
            //    atun_close_listening_sockets(cycle);
            //    atun_close_idle_connections(cycle);
            //}
        }

        if (atun_reopen) {
            //atun_reopen = 0;
            //atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "reopening logs");
            //atun_reopen_files(cycle, -1);
        }
    }
}

static void
atun_signal_worker_processes(int signo)
{
    atun_int_t      i;
    atun_err_t      err;
    
#if (1)    
    atun_channel_t  ch;
    atun_memzero(&ch, sizeof(atun_channel_t));
#endif
    
#if (ATUN_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case atun_signal_value(ATUN_SHUTDOWN_SIG):
        ch.command = ATUN_CMD_QUIT;
        break;

    case atun_signal_value(ATUN_TERMINATE_SIG):
        ch.command = ATUN_CMD_TERMINATE;
        break;

    case atun_signal_value(ATUN_REOPEN_SIG):
        ch.command = ATUN_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < atun_last_process; i++) {

#if (0)
        atun_log_debug7(ATUN_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       atun_processes[i].pid,
                       atun_processes[i].exiting,
                       atun_processes[i].exited,
                       atun_processes[i].detached,
                       atun_processes[i].respawn,
                       atun_processes[i].just_spawn);
#endif
        
        if (atun_processes[i].detached || atun_processes[i].pid == -1) {
            continue;
        }

        if (atun_processes[i].just_spawn) {
            atun_processes[i].just_spawn = 0;
            continue;
        }

        if (atun_processes[i].exiting
            && signo == atun_signal_value(ATUN_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (atun_write_channel(atun_processes[i].channel[0],
                                  &ch, sizeof(atun_channel_t), cycle->log)
                == ATUN_OK)
            {
                if (signo != atun_signal_value(ATUN_REOPEN_SIG)) {
                    atun_processes[i].exiting = 1;
                }

                continue;
            }
        }

        //atun_log_debug2(ATUN_LOG_DEBUG_CORE, cycle->log, 0,
        //               "kill (%P, %d)", atun_processes[i].pid, signo);

        if (kill(atun_processes[i].pid, signo) == -1) {
            err = atun_errno;
            //atun_log_error(ATUN_LOG_ALERT, cycle->log, err,
            //              "kill(%P, %d) failed", atun_processes[i].pid, signo);

            if (err == ATUN_ESRCH) {
                atun_processes[i].exited = 1;
                atun_processes[i].exiting = 0;
                atun_reap = 1;
            }

            continue;
        }

        if (signo != atun_signal_value(ATUN_REOPEN_SIGNAL)) {
            atun_processes[i].exiting = 1;
        }
    }
}

static atun_uint_t
atun_reap_children()
{
    atun_int_t         i, n;
    atun_uint_t        live;
    
#if (0)
    atun_channel_t     ch;
    atun_core_conf_t  *ccf;

    atun_memzero(&ch, sizeof(atun_channel_t));

    ch.command = ATUN_CMD_CLOSE_CHANNEL;
    ch.fd = -1;
#endif
    
    live = 0;
    for (i = 0; i < atun_last_process; i++) {

#if (0)
        atun_log_debug7(ATUN_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       atun_processes[i].pid,
                       atun_processes[i].exiting,
                       atun_processes[i].exited,
                       atun_processes[i].detached,
                       atun_processes[i].respawn,
                       atun_processes[i].just_spawn);
#endif
        
        if (atun_processes[i].pid == -1) {
            continue;
        }

        if (atun_processes[i].exited) {

            if (!atun_processes[i].detached) {
                
                //atun_close_channel(atun_processes[i].channel, cycle->log);

                //atun_processes[i].channel[0] = -1;
                //atun_processes[i].channel[1] = -1;

                //ch.pid = atun_processes[i].pid;
                //ch.slot = i;

                for (n = 0; n < atun_last_process; n++) {
                    
                    if (atun_processes[n].exited
                        || atun_processes[n].pid == -1
                        || atun_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    //atun_log_debug3(ATUN_LOG_DEBUG_CORE, cycle->log, 0,
                    //               "pass close channel s:%i pid:%P to:%P",
                    //               ch.slot, ch.pid, atun_processes[n].pid);

                    /* TODO: ATUN_AGAIN */

                    //atun_write_channel(atun_processes[n].channel[0],
                    //                  &ch, sizeof(atun_channel_t), cycle->log);
                }
            }

            if (atun_processes[i].respawn
                && !atun_processes[i].exiting
                && !atun_terminate
                && !atun_quit)
            {
                if (atun_spawn_process(atun_processes[i].proc,
                                      atun_processes[i].data,
                                      atun_processes[i].name, i)
                    == ATUN_INVALID_PID)
                {
                    //atun_log_error(ATUN_LOG_ALERT, cycle->log, 0,
                    //              "could not respawn %s",
                    //              atun_processes[i].name);
                    continue;
                }


                //ch.command = ATUN_CMD_OPEN_CHANNEL;
                //ch.pid = atun_processes[atun_process_slot].pid;
                //ch.slot = atun_process_slot;
                //ch.fd = atun_processes[atun_process_slot].channel[0];

                //atun_pass_open_channel(cycle, &ch);

                live = 1;

                continue;
            }

            if (atun_processes[i].pid == atun_new_binary) {

#if (0)
                ccf = (atun_core_conf_t *) atun_get_conf(cycle->conf_ctx,
                                                       atun_core_module);

                if (atun_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == ATUN_FILE_ERROR)
                {
                    atun_log_error(ATUN_LOG_ALERT, cycle->log, atun_errno,
                                  atun_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, atun_argv[0]);
                }

                atun_new_binary = 0;
                if (atun_noaccepting) {
                    atun_restart = 1;
                    atun_noaccepting = 0;
                }
#endif
            }

            if (i == atun_last_process - 1) {
                atun_last_process--;

            } else {
                atun_processes[i].pid = -1;
            }

        } else if (atun_processes[i].exiting || !atun_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}

static void
atun_master_process_exit()
{
#if (0)
    atun_uint_t  i;

    atun_delete_pidfile(cycle);

    atun_log_error(ATUN_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    atun_close_listening_sockets(cycle);

    /*
     * Copy atun_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard atun_cycle->log allocated from
     * atun_cycle->pool is already destroyed.
     */


    atun_exit_log = *atun_log_get_file_log(atun_cycle->log);

    atun_exit_log_file.fd = atun_exit_log.file->fd;
    atun_exit_log.file = &atun_exit_log_file;
    atun_exit_log.next = NULL;
    atun_exit_log.writer = NULL;

    atun_exit_cycle.log = &atun_exit_log;
    atun_exit_cycle.files = atun_cycle->files;
    atun_exit_cycle.files_n = atun_cycle->files_n;
    atun_cycle = &atun_exit_cycle;

    atun_destroy_pool(cycle->pool);
#endif
    
    exit(0);
}
