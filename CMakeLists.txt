cmake_minimum_required(VERSION 3.9)
project(inids C)

set(CMAKE_C_STANDARD 11)

include(FindPCAP.cmake)

add_executable(inids main.c capture/capture.h capture/capture.c utils/error_handler.h)
target_link_libraries(inids ${PCAP_LIBRARY})
