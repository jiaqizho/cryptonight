cmake_minimum_required(VERSION 3.5)
project(xmrig_cryptonight)

set(CMAKE_CXX_STANDARD 11)


# lib
set(HEADERS_CRYPTO
        src/crypto/keccak.h
        src/crypto/Algorithm.h

        src/crypto/c_blake256.h
        src/crypto/c_groestl.h
        src/crypto/c_jh.h
        src/crypto/c_skein.h
        src/crypto/CryptoNight.h
        src/crypto/CryptoNight_constants.h
        src/crypto/CryptoNight_monero.h
        src/crypto/CryptoNight_test.h
        src/crypto/groestl_tables.h
        src/crypto/hash.h
        src/crypto/skein_port.h
        src/crypto/soft_aes.h

        )

set(HEADERS_CRYPTO "${HEADERS_CRYPTO}" src/crypto/CryptoNight_arm.h)
# set(HEADERS_CRYPTO "${HEADERS_CRYPTO}" src/crypto/CryptoNight_x86.h)


set(SOURCES_CRYPTO
        src/crypto/keccak.cpp
        src/crypto/Algorithm.cpp

        src/crypto/c_groestl.c
        src/crypto/c_blake256.c
        src/crypto/c_jh.c
        src/crypto/c_skein.c

        )




# main

set(HEADERS src/xmrig.h)

include_directories(src)

add_executable(xmrig_cryptonight ${HEADERS} ${HEADERS_CRYPTO} ${SOURCES_CRYPTO}  src/main.cpp)