# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(SHA_SOURCES 
    ${SRC_DIR}/sha256.c 
    ${SRC_DIR}/sha256_consts.c 
    ${SRC_DIR}/sha256_compress_generic.c
    
    ${SRC_DIR}/sha512.c 
    ${SRC_DIR}/sha512_consts.c 
    ${SRC_DIR}/sha512_compress_generic.c
)

set(OPENSSL_DIR ${SRC_DIR}/openssl)

if(APPLE)
    set(OPENSSL_ASM_DIR ${OPENSSL_DIR}/macos)
else()
    set(OPENSSL_ASM_DIR ${OPENSSL_DIR}/linux)
endif()

set(OPENSSL_SOURCES 
    ${OPENSSL_DIR}/openssl_cpu_globals.c
)

if(X86_64)
    set(SHA_SOURCES ${SHA_SOURCES}
        ${SRC_DIR}/sha256_compress_x86_64_avx.c
        ${SRC_DIR}/sha512_compress_x86_64_avx.c
    )

    if(AVX2)
        set(SHA_SOURCES ${SHA_SOURCES}
            ${SRC_DIR}/sha256_compress_x86_64_avx2.c
            ${SRC_DIR}/sha512_compress_x86_64_avx2.c
        )
    endif()
    
    if(AVX512)
        set(SHA_SOURCES ${SHA_SOURCES}
            ${SRC_DIR}/sha256_compress_x86_64_avx512.c
            ${SRC_DIR}/sha512_compress_x86_64_avx512.c
        )
    endif()
    
    if(SHA_EXT)
        set(SHA_SOURCES ${SHA_SOURCES}
            ${SRC_DIR}/sha256_compress_x86_64_sha_ext.c
        )
    endif()

    set(OPENSSL_SOURCES ${OPENSSL_SOURCES}
        ${OPENSSL_ASM_DIR}/sha256-x86_64.s
        ${OPENSSL_ASM_DIR}/sha512-x86_64.s
    )
endif()

if(AARCH64)
    if(SHA_EXT)
        set(SHA_SOURCES ${SHA_SOURCES}
            ${SRC_DIR}/sha256_compress_aarch64_sha_ext.c
        )
    endif()
    
    set(OPENSSL_SOURCES ${OPENSSL_SOURCES}
        ${OPENSSL_ASM_DIR}/sha256-armv8.S
        ${OPENSSL_ASM_DIR}/sha512-armv8.S
    )
endif()

if(TEST_SPEED)
    set(MAIN_SOURCE ${TESTS_DIR}/main_speed.c)
else()
    set(MAIN_SOURCE ${TESTS_DIR}/main_tests.c)
endif()
