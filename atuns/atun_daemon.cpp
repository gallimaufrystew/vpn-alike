
#include "atun_sys.h"
#include "atun_err.h"

atun_int_t
atun_daemon()
{
    int  fd;

    switch (fork()) {
    case -1:
        return ATUN_ERROR;
    case 0:
        break;
    default:
        exit(0);
    }

    //atun_parent = atun_pid;
    //atun_pid = atun_getpid();

    if (setsid() == -1) {
        return ATUN_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        return ATUN_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        return ATUN_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        return ATUN_ERROR;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            return ATUN_ERROR;
        }
    }

    return ATUN_OK;
}
