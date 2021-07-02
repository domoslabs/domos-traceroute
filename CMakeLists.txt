cmake_minimum_required(VERSION 3.0)
project(domos_traceroute)

set(CMAKE_CXX_STANDARD 11)
set(
        SOURCES
)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_executable(domos_traceroute main.cpp ${SOURCES})
target_link_libraries(
        domos_traceroute
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/libPacket++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/libPcap++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/libCommon++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap/libpcap.so.1
)
target_include_directories(domos_traceroute PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/header)
