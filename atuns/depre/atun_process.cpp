
#include "atun_process.h"

int              atun_argc;
char           **atun_argv;
char           **atun_os_argv;

atun_int_t        atun_process_slot;
atun_sock_t     atun_channel;
atun_int_t        atun_last_process;
atun_process_t    atun_processes[4];

atun_pid_t
atun_spawn_process(atun_spawn_proc_pt proc, void *data,
    char *name, atun_int_t respawn)
{
    u_long     on;
    atun_pid_t  pid;
    atun_int_t  s;

    if (respawn >= 0) {
        s = respawn;
    } else {
        for (s = 0; s < atun_last_process; s++) {
            if (atun_processes[s].pid == -1) {
                break;
            }
        }
        if (s == ATUN_MAX_PROCESSES) {

            return ATUN_INVALID_PID;
        }
    }


    if (respawn != ATUN_PROCESS_DETACHED) {

#if (0)
        /* Solaris 9 still has no AF_LOCAL */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, atun_processes[s].channel) == -1)
        {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        atun_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       atun_processes[s].channel[0],
                       atun_processes[s].channel[1]);

        if (atun_nonblocking(atun_processes[s].channel[0]) == -1) {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          atun_nonblocking_n " failed while spawning \"%s\"",
                          name);
            atun_close_channel(atun_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (atun_nonblocking(atun_processes[s].channel[1]) == -1) {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          atun_nonblocking_n " failed while spawning \"%s\"",
                          name);
            atun_close_channel(atun_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        on = 1;
        if (ioctl(atun_processes[s].channel[0], FIOASYNC, &on) == -1) {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            atun_close_channel(atun_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(atun_processes[s].channel[0], F_SETOWN, atun_pid) == -1) {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            atun_close_channel(atun_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(atun_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            atun_close_channel(atun_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(atun_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            atun_log_error(NGX_LOG_ALERT, cycle->log, atun_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            atun_close_channel(atun_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
#endif
        //atun_channel = atun_processes[s].channel[1];

    } else {
        //atun_processes[s].channel[0] = -1;
        //atun_processes[s].channel[1] = -1;
    }

    atun_process_slot = s;

    pid = fork();

    switch (pid) {

    case -1:
        //atun_close_channel(atun_processes[s].channel, cycle->log);
        return ATUN_INVALID_PID;

    case 0:
        atun_parent = atun_pid;
        atun_pid = atun_getpid();
        proc(data);
        break;

    default:
        break;
    }
    
    atun_processes[s].pid = pid;
    atun_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    atun_processes[s].proc = proc;
    atun_processes[s].data = data;
    atun_processes[s].name = name;
    atun_processes[s].exiting = 0;

    switch (respawn) {

    case ATUN_PROCESS_NORESPAWN:
        atun_processes[s].respawn = 0;
        atun_processes[s].just_spawn = 0;
        //atun_processes[s].detached = 0;
        break;

    case ATUN_PROCESS_JUST_SPAWN:
        atun_processes[s].respawn = 0;
        atun_processes[s].just_spawn = 1;
        //atun_processes[s].detached = 0;
        break;

    case ATUN_PROCESS_RESPAWN:
        atun_processes[s].respawn = 1;
        atun_processes[s].just_spawn = 0;
        //atun_processes[s].detached = 0;
        break;

    case ATUN_PROCESS_JUST_RESPAWN:
        atun_processes[s].respawn = 1;
        atun_processes[s].just_spawn = 1;
        //atun_processes[s].detached = 0;
        break;

#if (0)
    case ATUN_PROCESS_DETACHED:
        atun_processes[s].respawn = 0;
        atun_processes[s].just_spawn = 0;
        //atun_processes[s].detached = 1;
        break;
#endif
    }

    if (s == atun_last_process) {
        atun_last_process++;
    }

    return pid;
}
