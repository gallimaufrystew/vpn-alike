
/*
 * File:   atun_os.h
 * Author: 19020107
 *
 * Created on April 29, 2018, 4:38 PM
 */

#ifndef ATUN_OS_H
#define ATUN_OS_H

#if _WIN32

class atun_win
{
    atun_win()
    {
        if (WSAStartup(MAKEWORD(2, 2), &ws_ver)) {
        }
    }

    ~atun_win()
    {
        WSACleanup();
    }
    
private:
    
    WSADATA ws_ver;
};

#endif

#endif /* ATUN_OS_H */
