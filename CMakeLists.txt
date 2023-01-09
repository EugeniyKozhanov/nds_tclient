cmake_minimum_required(VERSION 3.13)
project (MyTest VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(./external/openssl-cmake)

add_executable(test src/main.cpp src/SslExample.cpp)
target_link_libraries(test crypto)

nds_create_rom(test)
