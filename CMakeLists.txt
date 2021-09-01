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
# Build the jsoncpp library
ExternalProject_Add(
        jsoncpp
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp
        PATCH_COMMAND mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/build
        BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/build
        BUILD_COMMAND cmake -D JSONCPP_WITH_TESTS=OFF JSONCPP_WITH_POST_BUILD_UNITTEST=OFF BUILD_SHARED_LIBS=OFF BUILD_OBJECT_LIBS=OFF .. COMMAND make
        INSTALL_COMMAND ""
)
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
# Build the libbzip2 library
ExternalProject_Add(
        libbzip2
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/bzip2
        CONFIGURE_COMMAND ""
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/third-party/bzip2
        BUILD_COMMAND make libbz2.a
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
)
add_executable(domos-traceroute src/main.cpp ${SOURCES})
# We need this
find_package(Threads REQUIRED)
# Add dependencies, so that cmake knows what to build in what order
#add_dependencies(pcapplusplus libpcap)
add_dependencies(domos-traceroute pcapplusplus)
add_dependencies(domos-traceroute jsoncpp)
add_dependencies(domos-traceroute libbzip2)

# EXCLUDE_FROM_ALL makes it so that random is not installed when calling make install...
add_subdirectory(third-party/random EXCLUDE_FROM_ALL)
add_subdirectory(third-party/argparse EXCLUDE_FROM_ALL)

# Add the pcapplusplus header
target_include_directories(
        domos-traceroute
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/header
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/bzip2
)

# Link the built libraries, so that we can use them in our code
target_link_libraries(
        domos-traceroute PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPcap++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPacket++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libCommon++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/build/lib/libjsoncpp.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/bzip2/libbz2.a
        effolkronium_random
        argparse
        Threads::Threads
        pcap
)
install(TARGETS domos-traceroute)