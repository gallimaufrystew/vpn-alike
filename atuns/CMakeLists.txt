
cmake_minimum_required(VERSION 2.6)

project(atuns)

add_definitions(-DUSE_EPOLL)
add_definitions(-DHAVE_IOCTL)

include_directories(. /opt/include ./mem)

# Source files to be used in the library
file (GLOB app_SOURCES *.cpp mem/*.c)

set(OPENSSL_ROOT_DIR /opt)

find_package(OpenSSL)

if (OPENSSL_FOUND)
    add_executable(atuns ${app_SOURCES})
    target_link_libraries(atuns ${OPENSSL_LIBRARIES})
else()
    message(SEND_ERROR "no openssl library found")
endif()
