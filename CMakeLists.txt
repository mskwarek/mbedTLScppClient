cmake_minimum_required(VERSION 3.5)
project(cppClient)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

set(libs
        pthread
        mbedtls
        mbedx509
        mbedcrypto)

set(SOURCE_FILES
    DefaultConfig.cpp
    DefaultConfig.h
    mbed_tests.cpp
    SslClient.cpp
    SslClient.h
    Usage.c)

include_directories(${CMAKE_SOURCE_DIR}/../mbedtls/include)
link_directories(${CMAKE_SOURCE_DIR}/../mbedtls/library)


add_executable(cppClient ${SOURCE_FILES})
target_link_libraries(cppClient ${libs})