
/* 
 * File:   atun_process.h
 * Author: 19020107
 *
 * Created on May 16, 2018, 10:24 AM
 */

#ifndef ATUN_PROCESS_H
#define ATUN_PROCESS_H

//#include <atun_setproctitle.h>

typedef pid_t  atun_pid_t;
typedef atun_uint_t atun_msec_t;

#define ATUN_INVALID_PID  -1

typedef void (*atun_spawn_proc_pt) (void *data);

typedef struct {
    atun_pid_t           pid;
    int                 status;
    //atun_sock_t        channel[2];

    atun_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            just_spawn:1;
    //unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
} atun_process_t;

#define ATUN_MAX_PROCESSES         4

#define ATUN_PROCESS_NORESPAWN     -1
#define ATUN_PROCESS_JUST_SPAWN    -2
#define ATUN_PROCESS_RESPAWN       -3
#define ATUN_PROCESS_JUST_RESPAWN  -4
#define ATUN_PROCESS_DETACHED      -5

#define atun_getpid   getpid
#define atun_getppid  getppid

atun_pid_t atun_spawn_process(atun_spawn_proc_pt proc, void *data, char *name, atun_int_t respawn);

//atun_int_t atun_init_signals(atun_log_t *log);

#if (HAVE_SCHED_YIELD)
#define atun_sched_yield()  sched_yield()
#else
#define atun_sched_yield()  usleep(1)
#endif

#define atun_signal_helper(n)     SIG##n
#define atun_signal_value(n)      atun_signal_helper(n)

/* TODO: #ifndef */
#define ATUN_SHUTDOWN_SIG      QUIT
#define ATUN_TERMINATE_SIG     TERM
#define ATUN_NOACCEPT_SIG      WINCH
#define ATUN_RECONFIGURE_SIG   HUP

#if (ATUN_LINUXTHREADS)
#define ATUN_REOPEN_SIG       INFO
#define ATUN_CHANGEBIN_SIG     XCPU
#else
#define ATUN_REOPEN_SIG        USR1
#define ATUN_CHANGEBIN_SIG     USR2
#endif

extern int            atun_argc;
extern char         **atun_argv;
extern char         **atun_os_argv;

extern atun_pid_t      atun_pid;
extern atun_pid_t      atun_parent;
extern atun_sock_t   atun_channel;
extern atun_int_t      atun_process_slot;
extern atun_int_t      atun_last_process;
extern atun_process_t  atun_processes[ATUN_MAX_PROCESSES];

#endif /* ATUN_PROCESS_H */
