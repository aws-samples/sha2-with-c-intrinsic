# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CLANG 1)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O3 -fPIC -std=c99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -Wall -Wextra -Werror -Wpedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings -Wformat-security -Wcast-qual -Wunused-result")

if(X86_64)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -mno-red-zone")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=native")
endif()

# Avoiding GCC 4.8 bug
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces -Wno-missing-field-initializers")

if(CLANG)
    # CMAKE sends the `-isystem` flag to clang for assembly files.
    # Currently clang unrecognizes it.
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -Wno-error=unused-command-line-argument")
endif ()

set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -ggdb -fPIC -Wall -Wextra -Werror -Wpedantic")

if(MSAN)
    if(NOT CLANG)
        message(FATAL_ERROR "Cannot enable MSAN unless using Clang")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer")
endif()

if(ASAN)
    if(NOT CLANG)
        message(FATAL_ERROR "Cannot enable ASAN unless using Clang")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
endif()

if(TSAN)
    if(NOT CLANG)
        message(FATAL_ERROR "Cannot enable TSAN unless using Clang")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
endif()

if(UBSAN)
    if(NOT CLANG)
        message(FATAL_ERROR "Cannot enable UBSAN unless using Clang")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
endif()

if(TEST_SPEED)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTEST_SPEED -DRTDSC")
endif()

if(ALTERNATIVE_AVX512_IMPL)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DALTERNATIVE_AVX512_IMPL")
endif()

if(DONT_USE_UNROLL_PRAGMA)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDONT_USE_UNROLL_PRAGMA")
endif()

if(MONTE_CARLO_NUM_OF_TESTS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMONTE_CARLO_NUM_OF_TESTS=${MONTE_CARLO_NUM_OF_TESTS}")
endif()
