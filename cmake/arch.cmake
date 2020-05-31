# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(x86_64|amd64|AMD64)$")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DX86_64")
  set(X86_64 1)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(aarch64|arm64|arm64e)$")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAARCH64 -DNEON_SUPPORT")
  set(AARCH64 1)
endif()

# Only little endian systems are supported
try_run(RUN_RESULT COMPILE_RESULT
        "${CMAKE_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/cmake/test_endianess.c"
        COMPILE_DEFINITIONS "-Werror -Wall -Wpedantic"
        OUTPUT_VARIABLE OUTPUT
)

if((NOT ${COMPILE_RESULT}) OR (NOT RUN_RESULT EQUAL 0))
    message(FATAL "Only little endian systems are supported")
endif()

if(X86_64)
    # Test AVX2
    try_run(RUN_RESULT COMPILE_RESULT
            "${CMAKE_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/cmake/test_x86_64_avx2.c"
            COMPILE_DEFINITIONS "-march=native -Werror -Wall -Wpedantic"
            OUTPUT_VARIABLE OUTPUT
    )

    if(${COMPILE_RESULT} AND (RUN_RESULT EQUAL 0))
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAVX2_SUPPORT")
        set(AVX2 1)        
    else()
        message(STATUS "The AVX2 implementation is not supported")
    endif()

    # Test AVX512
    try_run(RUN_RESULT COMPILE_RESULT
            "${CMAKE_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/cmake/test_x86_64_avx512.c"
            COMPILE_DEFINITIONS "-march=native -Werror -Wall -Wpedantic"
            OUTPUT_VARIABLE OUTPUT
    )

    if(${COMPILE_RESULT} AND (RUN_RESULT EQUAL 0))
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAVX512_SUPPORT")
        set(AVX512 1)        
    else()
        message(STATUS "The AVX512 implementation is not supported")
    endif()
    
    # Test SHA extension
    try_run(RUN_RESULT COMPILE_RESULT
            "${CMAKE_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/cmake/test_x86_64_sha_ni.c"
            COMPILE_DEFINITIONS "-march=native -Werror -Wall -Wpedantic"
            OUTPUT_VARIABLE OUTPUT
    )

    if(${COMPILE_RESULT} AND (RUN_RESULT EQUAL 0))
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DX86_64_SHA_SUPPORT")
        set(SHA_EXT 1)
    else()
        message(STATUS "The SHA_EXT implementation is not supported")
    endif()
endif()

if(AARCH64)
    # Test AVX2
    try_run(RUN_RESULT COMPILE_RESULT
            "${CMAKE_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/cmake/test_aarch64_sha_ni.c"
            COMPILE_DEFINITIONS "-I${INCLUDE_DIR}/internal -mcpu=native -Werror -Wall -Wpedantic"
            OUTPUT_VARIABLE OUTPUT
    )

    if(${COMPILE_RESULT} AND (RUN_RESULT EQUAL 0))
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAARCH64_SHA_SUPPORT")
        set(SHA_EXT 1)        
    else()
        message(STATUS "The SHA_EXT implementation is not supported")
    endif()
endif()
