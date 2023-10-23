cmake_minimum_required(VERSION 3.26)
project(loadlibrary-ex)

set(CMAKE_CXX_STANDARD 23)

add_executable(loadlibrary-ex WIN32 src/main.cpp)

# Statically link CRT.
set_property(TARGET loadlibrary-ex PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Included libraries.
include_directories(deps/phnt)