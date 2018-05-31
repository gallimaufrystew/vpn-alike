
/*
 * File:   atun_main.h
 * Author: 19020107
 *
 * Created on May 16, 2018, 10:06 AM
 */

#ifndef ATUN_MAIN_H
#define ATUN_MAIN_H

#define atun_version      000001
#define ATUN_VERSION      "0.0.1"
#define ATUN_VER          "atuns/" ATUN_VERSION

#ifdef ATUN_BUILD
    #define ATUN_VER_BUILD    ATUN_VER " (" ATUN_BUILD ")"
#else
    #define ATUN_VER_BUILD    ATUN_VER
#endif

#define ATUN_VAR          "ATUN"

#define ATUN_LINEFEED     "\x0a"

#endif /* ATUN_MAIN_H */
