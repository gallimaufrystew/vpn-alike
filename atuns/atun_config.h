
/*
 * File:   atun_config.h
 * Author: 19020107
 *
 * Created on April 29, 2018, 5:47 PM
 */

#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

#include "atun_sys.h"
#include "atun_err.h"

typedef atun_int_t atun_port_t;
typedef std::pair<std::string, atun_port_t> addr_port;
typedef std::unordered_map<atun_port_t, addr_port> port_map_t;

atun_int_t atun_config_init();

#endif
