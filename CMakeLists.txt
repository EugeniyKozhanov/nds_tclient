cmake_minimum_required(VERSION 3.13)
project (MyTest VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(./external/openssl-cmake)
add_subdirectory(./external/zlib)

if (NDS_PORT)
	add_executable(test src/main.cpp src/SslExample.cpp)
	target_link_libraries(test crypto)

	nds_create_rom(test)
endif()

if (NOT NDS_PORT)
	add_subdirectory(./test)
endif()
