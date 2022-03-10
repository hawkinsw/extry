cmake_minimum_required(VERSION 3.15)

project(extry VERSION 1.0 DESCRIPTION "An ELF entry point hijacker")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(LibElf REQUIRED)

include_directories("include/")
include_directories("deps/args/")
include_directories(${LIBELF_INCLUDE_DIRS})

add_executable(extry main.cpp extry.cpp)
target_link_libraries(extry PRIVATE elf)
target_compile_options(extry PRIVATE ${DEFINES})
