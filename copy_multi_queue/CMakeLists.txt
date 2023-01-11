cmake_minimum_required(VERSION 3.24)
project(copy_multi_queue C)

set(CMAKE_C_STANDARD 23)

add_executable(copy_multi_queue main.c)
target_link_libraries(copy_multi_queue uring)
