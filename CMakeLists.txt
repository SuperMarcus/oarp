cmake_minimum_required(VERSION 3.8)
project(oarp)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/local/opt/libpcap/include /usr/local/opt/libnet/include /usr/local/opt/libev/include)
link_directories(/usr/local/opt/libpcap/lib /usr/local/opt/libnet/lib /usr/local/opt/libev/lib)

set(SOURCE_FILES oarp_main.cpp oarp.cpp oarp.h oarp_target.cpp macros.h oarp_arp.cpp)
add_executable(oarp ${SOURCE_FILES})
target_link_libraries(oarp libnet.a libpcap.a libev.a)
