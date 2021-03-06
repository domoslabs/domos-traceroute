cmake_minimum_required(VERSION 3.0)
project(domos_traceroute)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
set(
        SOURCES
        src/Probe.cpp
        src/Utilities.cpp
        src/Traceroute.cpp
        src/Capture.cpp include/Capture.h
        src/ProbeRegister.cpp include/ProbeRegister.h)
# Disable building tests for random library
option(Random_BuildTests "Build the unit tests" ON)
set(Random_BuildTests OFF)

include(ExternalProject)
find_package(PkgConfig)
# Find the jsoncpp library


if (${jsoncpp_FOUND})
    MESSAGE(STATUS "jsoncpp found via CMake")
else (${jsoncpp_FOUND})
    MESSAGE(STATUS "jsoncpp not found via CMake, trying pkg-config")
    pkg_search_module(JSONCPP REQUIRED jsoncpp)
endif (${jsoncpp_FOUND})
# Find the libpcap library
find_package(PCAP REQUIRED)
# Build the pcapplusplus library
ExternalProject_Add(
        pcapplusplus
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/configure-linux.sh --default
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus
        BUILD_COMMAND make libs
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
)
add_executable(domos-traceroute src/main.cpp ${SOURCES})
# We need this
find_package(Threads REQUIRED)
# Add dependencies, so that cmake knows what to build in what order
#add_dependencies(pcapplusplus libpcap)
add_dependencies(domos-traceroute pcapplusplus)

# Add the pcapplusplus header
target_include_directories(
        domos-traceroute
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/header
        PRIVATE ${JSONCPP_INCLUDE_DIRS}
)

# Link the built libraries, so that we can use them in our code
target_link_libraries(
        domos-traceroute PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPcap++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPacket++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libCommon++.a
        ${JSONCPP_LIBRARIES}
        Threads::Threads
        pcap
)
install(TARGETS domos-traceroute)