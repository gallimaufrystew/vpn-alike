
///
/// simple configuration
///

#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

int init_port_mapping();

#ifdef __linux__

extern volatile sig_atomic_t running;

#elif _WIN32

extern volatile bool running;
#pragma warning (disable: 4996)

#ifdef max
#undef max
#endif

#endif

#endif
