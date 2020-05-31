// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "sha.h"
#include "test.h"

#define SHA256_TEST_MAX_MSG_BYTE_LEN (6400)
#define SHA512_TEST_MAX_MSG_BYTE_LEN (12800)

#if !defined(MONTE_CARLO_NUM_OF_TESTS)
#  define MONTE_CARLO_NUM_OF_TESTS (100000)
#endif

_INLINE_ int test_sha256_impl(IN const sha_impl_t impl,
                              IN const uint8_t *data,
                              IN const uint8_t *ref_dgst,
                              IN const size_t   byte_len)
{
  uint8_t tst_dgst[SHA256_HASH_BYTE_LEN] = {0};
  sha256(tst_dgst, data, byte_len, impl);

  if(0 != memcmp(ref_dgst, tst_dgst, SHA256_HASH_BYTE_LEN)) {
    printf("Digest mismatch for impl=%d and size=%ld\n", impl, byte_len);
    print(ref_dgst, SHA256_HASH_BYTE_LEN);
    print(tst_dgst, SHA256_HASH_BYTE_LEN);
    return FAILURE;
  }

  return SUCCESS;
}

_INLINE_ int test_sha256()
{
  uint8_t ref_dgst[SHA256_HASH_BYTE_LEN]     = {0};
  uint8_t data[SHA256_TEST_MAX_MSG_BYTE_LEN] = {0};

  // Use a deterministic seed.
  srand(0);
  rand_data(data, sizeof(data));

  printf("Testing SHA256 Short/Long tests\n");

  for(size_t byte_len = 0; byte_len <= sizeof(data); byte_len++) {
    SHA256(data, byte_len, ref_dgst);

    GUARD(test_sha256_impl(GENERIC_IMPL, data, ref_dgst, byte_len));

    // X86-64 specific options
    RUN_X86_64(GUARD(test_sha256_impl(AVX_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX2(GUARD(test_sha256_impl(AVX2_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX512(GUARD(test_sha256_impl(AVX512_IMPL, data, ref_dgst, byte_len)););
    RUN_X86_64_SHA_EXT(
      GUARD(test_sha256_impl(SHA_EXT_IMPL, data, ref_dgst, byte_len)););

    // Aarch64 specific options
    RUN_AARCH64_SHA_EXT(
      GUARD(test_sha256_impl(SHA_EXT_IMPL, data, ref_dgst, byte_len)););
  }

  printf("Testing SHA256 Monte Carlo tests\n");

  // Perform 100,000 Monte Carlo tests.
  for(size_t i = 0; i < MONTE_CARLO_NUM_OF_TESTS; i++) {

    printf("\rTesting case=%ld", i);

    // Generate a random message and a reference digest.
    size_t byte_len = rand() % sizeof(data);
    rand_data(data, byte_len);
    SHA256(data, byte_len, ref_dgst);

    // X86-64 specific options
    RUN_X86_64(GUARD(test_sha256_impl(AVX_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX2(GUARD(test_sha256_impl(AVX2_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX512(GUARD(test_sha256_impl(AVX512_IMPL, data, ref_dgst, byte_len)););
    RUN_X86_64_SHA_EXT(
      GUARD(test_sha256_impl(SHA_EXT_IMPL, data, ref_dgst, byte_len)););

    // Aarch64 specific options
    RUN_AARCH64_SHA_EXT(
      GUARD(test_sha256_impl(SHA_EXT_IMPL, data, ref_dgst, byte_len)););
  }

  printf("\n");
  return SUCCESS;
}

_INLINE_ int test_sha512_impl(IN const sha_impl_t impl,
                              IN const uint8_t *data,
                              IN const uint8_t *ref_dgst,
                              IN const size_t   byte_len)
{
  uint8_t tst_dgst[SHA512_HASH_BYTE_LEN] = {0};
  sha512(tst_dgst, data, byte_len, impl);

  if(0 != memcmp(ref_dgst, tst_dgst, SHA512_HASH_BYTE_LEN)) {
    printf("Digest mismatch for impl=%d and size=%ld\n", impl, byte_len);
    print(ref_dgst, SHA512_HASH_BYTE_LEN);
    print(tst_dgst, SHA512_HASH_BYTE_LEN);
    return FAILURE;
  }

  return SUCCESS;
}

_INLINE_ int test_sha512()
{
  uint8_t ref_dgst[SHA512_HASH_BYTE_LEN]     = {0};
  uint8_t data[SHA512_TEST_MAX_MSG_BYTE_LEN] = {0};

  // Use a deterministic seed.
  srand(0);
  rand_data(data, sizeof(data));

  printf("Testing SHA512 Short/Long tests\n");

  for(size_t byte_len = 0; byte_len <= sizeof(data); byte_len++) {
    SHA512(data, byte_len, ref_dgst);

    GUARD(test_sha512_impl(GENERIC_IMPL, data, ref_dgst, byte_len));

    // X86-64 specific options
    RUN_X86_64(GUARD(test_sha512_impl(AVX_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX2(GUARD(test_sha512_impl(AVX2_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX512(GUARD(test_sha512_impl(AVX512_IMPL, data, ref_dgst, byte_len)););
  }

  printf("Testing SHA512 Monte Carlo tests\n");

  // Perform 100,000 Monte Carlo tests.
  for(size_t i = 0; i < MONTE_CARLO_NUM_OF_TESTS; i++) {

    printf("\rTesting case=%ld", i);

    // Generate a random message and a reference digest.
    size_t byte_len = rand() % sizeof(data);
    rand_data(data, byte_len);
    SHA512(data, byte_len, ref_dgst);

    GUARD(test_sha512_impl(GENERIC_IMPL, data, ref_dgst, byte_len));

    // X86-64 specific options
    RUN_X86_64(GUARD(test_sha512_impl(AVX_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX2(GUARD(test_sha512_impl(AVX2_IMPL, data, ref_dgst, byte_len)););
    RUN_AVX512(GUARD(test_sha512_impl(AVX512_IMPL, data, ref_dgst, byte_len)););
  }

  printf("\n");
  return SUCCESS;
}

int main(void)
{
  GUARD(test_sha256());
  GUARD(test_sha512());

  return 0;
}
