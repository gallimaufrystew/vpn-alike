
/*
 * File:   atun_signal.h
 * Author: 19020107
 *
 * Created on April 11, 2018
 */

#ifndef TUN_SIGNAL_INCLUDED_H
#define TUN_SIGNAL_INCLUDED_H

#include "atun_sys.h"
#include "atun_err.h"

#if __linux__

typedef struct {
    int sig_no;
    const char *sig_name;
    void (*handler)(int sig_no);
} signal_t;

atun_int_t atun_signal_init();
void signal_handler(int sig_no);

#elif _WIN32

BOOL WINAPI atun_signal_handler(DWORD ctrl_type);

#endif //!

#endif // TUN_SIGNAL_INCLUDED_H
