cmake_minimum_required(VERSION 3.5)

project(overflow)

set(SOURCES
    src/TEA.cpp
    src/RC4.cpp
    src/overflow.cpp
)

set(CMAKE_CXX_FLAGS 
    "${CMAKE_CXX_FLAGS} -z execstack -fno-stack-protector -no-pie -z norelro"
)

add_executable(overflow ${SOURCES})

target_include_directories(overflow
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)