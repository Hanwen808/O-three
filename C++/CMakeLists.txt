cmake_minimum_required(VERSION 3.28)
project(O3Skt)

set(CMAKE_CXX_STANDARD 23)

add_executable(O3Skt main.cpp
        Sources/MurmurHash3.cpp
        Sources/Lean.cpp
        Headers/O3Skt.h
        Sources/O3Skt.cpp
        Headers/LeanCF.h
        Sources/LeanCF.cpp)
