cmake_minimum_required(VERSION 3.15)

project(extry VERSION 1.0 DESCRIPTION "An ELF entry point hijacker")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(LibElf REQUIRED)

include_directories("include/")
include_directories("deps/args/")
include_directories(${LIBELF_INCLUDE_DIRS})

add_executable(extry main.cpp extry.cpp)
target_link_libraries(extry PRIVATE "Zydis" elf)
target_compile_options(extry PRIVATE ${DEFINES})
