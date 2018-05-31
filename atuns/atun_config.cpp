
#include "atun_config.h"

port_map_t port_map;

atun_int_t atun_config_init()
{
    std::ifstream ifs("atuns.conf");
    std::string line;

    if (!ifs.is_open()) {
        std::cout << "configuration file doesn't exist" << "\n";
        exit(-1);
    }

    while (std::getline(ifs, line)) {
        std::string key, first, second;
        std::istringstream is(line);
        is >> key >> first >> second;
        if (!key.empty()) {
            if (key[0] == '#') {
                continue;
            }
            port_map[std::atoi(key.c_str())] =
                std::make_pair(first, std::atoi(second.c_str()));
        }
    }
    ifs.close();

    return ATUN_OK;
}
