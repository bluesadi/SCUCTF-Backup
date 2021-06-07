cmake_minimum_required(VERSION 3.5)

project(twin)

set(SOURCES
    src/twin.cpp
)

set(CMAKE_CXX_FLAGS 
    "${CMAKE_CXX_FLAGS}"
)

add_executable(twin ${SOURCES})

target_include_directories(twin
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)