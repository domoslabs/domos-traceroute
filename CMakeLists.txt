cmake_minimum_required(VERSION 3.0)
project(domos_traceroute)

set(CMAKE_CXX_STANDARD 11)
set(
        SOURCES
)
include(ExternalProject)
ExternalProject_Add(
        libpcap
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap/configure --prefix=${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap
        BUILD_COMMAND make
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
)
ExternalProject_Add(
        pcapplusplus
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/configure-linux.sh --default
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus
        BUILD_COMMAND make libs
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(domos_traceroute main.cpp ${SOURCES})

add_dependencies(pcapplusplus libpcap)
add_dependencies(domos_traceroute pcapplusplus)
target_include_directories(domos_traceroute PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/header)
target_link_libraries(
        domos_traceroute
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPcap++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPacket++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libCommon++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap/libpcap.a
)
