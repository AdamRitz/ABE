cmake_minimum_required(VERSION 4.0)
project(CPABE)

set(CMAKE_CXX_STANDARD 20)

include_directories(
        "D:/Software/Code/Lib/PBC/pbc-1.0.0/pbc-1.0.0/include"
        "D:/Software/Code/Lib/GMP/gmp-6.3.0/gmp-6.3.0"
        "D:/Software/Code/Lib/OpenSSL-Win32/include/"
        "D:/Software/Code/Lib/NTL/ntl-11.6.0/ntl-11.6.0/include"
)

# 2. 库目录（注意这里是 pbc-1.0.0 根目录，不是 include）
link_directories(
        "D:/Software/Code/Lib/GMP/gmp-6.3.0/gmp-6.3.0/.libs"
        "D:/Software/Code/Lib/PBC/pbc-1.0.0/pbc-1.0.0"
        "D:/Software/Code/Lib/OpenSSL-Win32/lib/"
        "D:/Software/Code/Lib/NTL/ntl-11.6.0/ntl-11.6.0/src"
)
add_executable(CPABE main.cpp)
add_executable(test test.cpp)
# 3. 只用库名就行，CMake 会在上面的目录里找 libpbc.a / libgmp.a
target_link_libraries(CPABE ntl pbc gmp libssl libcrypto)
target_link_libraries(test ntl pbc gmp libssl libcrypto)