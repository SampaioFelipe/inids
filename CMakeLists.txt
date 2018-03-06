cmake_minimum_required(VERSION 3.9)
project(inids C)

set(CMAKE_C_STANDARD 11)

include(FindPCAP.cmake)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(inids main.c capture/capture.h capture/capture.c globals/error_handler.h globals/encoding.h analysis/analysis.c analysis/analysis.h globals/threads_manager.c globals/threads_manager.h)
target_link_libraries(inids ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
