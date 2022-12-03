cmake_minimum_required(VERSION 3.23)
project(.)

set(CMAKE_CXX_STANDARD 20)

find_library(PCAP_LIBRARY
        NAMES . wpcap
        HINTS ${PCAP_ROOT_DIR}/lib
        )

add_executable(. main.cpp src/reader.cpp src/reader.h)
target_link_libraries(. ${PCAP_LIBRARY})
