cmake_minimum_required(VERSION 3.22.1)
project(payload)

find_package(lsplant REQUIRED CONFIG)
find_package(shadowhook REQUIRED CONFIG)

add_library(payload SHARED main.cpp hooks.cpp)

target_link_libraries(payload
    lsplant::lsplant
    shadowhook::shadowhook
    log
    android
)
