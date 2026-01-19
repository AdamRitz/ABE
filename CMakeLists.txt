cmake_minimum_required(VERSION 3.20)
project(CPABE LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 让 CMake 优先在 /ucrt64 下找头文件和库（仅在 MSYS 路径生效）
list(PREPEND CMAKE_PREFIX_PATH "/ucrt64")

find_package(OpenSSL REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# PBC
find_path(PBC_INCLUDE_DIR NAMES pbc/pbc.h PATHS /ucrt64/include REQUIRED)
find_library(PBC_LIBRARY NAMES pbc PATHS /ucrt64/lib REQUIRED)

# GMP / NTL
find_library(GMP_LIBRARY NAMES gmp PATHS /ucrt64/lib REQUIRED)
find_library(NTL_LIBRARY NAMES ntl PATHS /ucrt64/lib REQUIRED)
find_path(NTL_INCLUDE_DIR NAMES NTL/mat_ZZ_p.h PATHS /ucrt64/include REQUIRED)

# === 关键：把 proto 生成的 .cc 编译成一个库，供 client/server 链接 ===
add_library(proto_objs
        Service.pb.cc
        Service.grpc.pb.cc
)
target_link_libraries(proto_objs PUBLIC protobuf::libprotobuf gRPC::grpc++)
target_include_directories(proto_objs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(CPABE main.cpp)
add_executable(test  test.cpp)
add_executable(server Server.cpp)

foreach(tgt CPABE test server)
    target_include_directories(${tgt} PRIVATE
            ${PBC_INCLUDE_DIR}
            ${NTL_INCLUDE_DIR}
    )
    target_link_libraries(${tgt} PRIVATE
            proto_objs             # <<< 关键
            gRPC::grpc++           # <<< 关键（有时 proto_objs 已带，但加上更稳）
            protobuf::libprotobuf  # <<< 关键（同上）
            ${PBC_LIBRARY}
            ${GMP_LIBRARY}
            ${NTL_LIBRARY}
            OpenSSL::SSL
            OpenSSL::Crypto
    )
endforeach()
