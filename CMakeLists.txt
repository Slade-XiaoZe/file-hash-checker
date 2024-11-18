cmake_minimum_required(VERSION 3.16)
project(file_hash_checker)

set(CMAKE_CXX_STANDARD 11)

# 手动指定 OpenSSL 的路径
set(OPENSSL_ROOT_DIR "A:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MTd/libcrypto_static.lib")

# 添加可执行文件
add_executable(file_hash_checker main.cpp)

# 链接 OpenSSL 库
target_include_directories(file_hash_checker PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(file_hash_checker PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
