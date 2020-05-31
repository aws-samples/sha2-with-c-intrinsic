cmake_minimum_required(VERSION 3.0.0)
project (sha-with-intrinsic C ASM)

set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(TESTS_DIR ${PROJECT_SOURCE_DIR}/tests)

include_directories(${INCLUDE_DIR})
include_directories(${INCLUDE_DIR}/internal)

include(cmake/arch.cmake)

include(cmake/compilation-flags.cmake)

# Depends on SRC_DIR
# and on arch.cmake
include(cmake/sources.cmake)

include(cmake/clang-format.cmake)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
 
               ${SHA_SOURCES}
               ${OPENSSL_SOURCES}
               ${MAIN_SOURCE}
)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
