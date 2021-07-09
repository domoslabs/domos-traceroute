cmake_minimum_required(VERSION 3.0)
project(domos_traceroute)

set(CMAKE_CXX_STANDARD 11)
# Need this for multithreading
set(CMAKE_CXX_FLAGS)

set(
        SOURCES
        src/Probe.cpp
        src/Utilities.cpp
        src/Traceroute.cpp
        src/Capture.cpp include/Capture.h
        src/ProbeRegister.cpp include/ProbeRegister.h)
include(ExternalProject)
# Build the jsoncpp library
ExternalProject_Add(
        jsoncpp
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp
        PATCH_COMMAND  mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/build
        BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/build
        BUILD_COMMAND cmake -D JSONCPP_WITH_TESTS=OFF JSONCPP_WITH_POST_BUILD_UNITTEST=OFF BUILD_SHARED_LIBS=OFF BUILD_OBJECT_LIBS=OFF .. COMMAND make
        INSTALL_COMMAND ""
)
# Build the libpcap library
ExternalProject_Add(
        libpcap
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap/configure --prefix=${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap
        BUILD_COMMAND make
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
)
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

add_executable(domos_traceroute src/main.cpp ${SOURCES})
# We need this
find_package(Threads REQUIRED)
# Add dependencies, so that cmake knows what to build in what order
add_dependencies(pcapplusplus libpcap)
add_dependencies(domos_traceroute pcapplusplus)
add_dependencies(domos_traceroute jsoncpp)

# Add the pcapplusplus header
target_include_directories(
        domos_traceroute
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/header
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/include
)

# Link the built libraries, so that we can use them in our code
target_link_libraries(
        domos_traceroute PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPcap++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libPacket++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/pcapplusplus/Dist/libCommon++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libpcap/libpcap.a
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/jsoncpp/build/lib/libjsoncpp.a
        Threads::Threads
)
