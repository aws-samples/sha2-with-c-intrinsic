// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "measurements.h"
#include "sha.h"
#include "test.h"

#define MAX_MSG_BYTE_LEN (65536UL)

_INLINE_ void speed_sha256(void)
{
  uint8_t dgst[SHA256_HASH_BYTE_LEN] = {0};
  uint8_t data[MAX_MSG_BYTE_LEN]     = {0};

  // Use a deterministic seed.
  srand(0);
  rand_data(data, sizeof(data));

  printf("\nSHA-256 Benchmark:");
  printf("\n------------------\n");
  printf("        msg     generic");

  // X86-64 specific options
  RUN_X86_64(printf("      avx (C)   avx (ossl)"););
  RUN_AVX2(printf("     avx2 (C)  avx2 (ossl)"););
  RUN_AVX512(printf("   avx512 (C)"););
  RUN_X86_64_SHA_EXT(printf("  sha ext (C) sha ext (ossl) \n"););

  // Aarch64 specific options
  RUN_NEON(printf("  neon (ossl)"););
  RUN_AARCH64_SHA_EXT(printf("  sha ext (C) sha ext (ossl) \n"););

  printf("\n");
  for(size_t msg_byte_len = 1; msg_byte_len <= MAX_MSG_BYTE_LEN;
      msg_byte_len <<= 1) {

    printf("%5ld bytes", msg_byte_len);
    MEASURE(sha256(dgst, data, msg_byte_len, GENERIC_IMPL););

    // X86-64 specific options
    RUN_X86_64(MEASURE(sha256(dgst, data, msg_byte_len, AVX_IMPL);););
    RUN_X86_64(MEASURE(sha256(dgst, data, msg_byte_len, OPENSSL_AVX_IMPL);););
    RUN_AVX2(MEASURE(sha256(dgst, data, msg_byte_len, AVX2_IMPL);););
    RUN_AVX2(MEASURE(sha256(dgst, data, msg_byte_len, OPENSSL_AVX2_IMPL);););
    RUN_AVX512(MEASURE(sha256(dgst, data, msg_byte_len, AVX512_IMPL);););
    RUN_X86_64_SHA_EXT(MEASURE(sha256(dgst, data, msg_byte_len, SHA_EXT_IMPL);););
    RUN_X86_64_SHA_EXT(
      MEASURE(sha256(dgst, data, msg_byte_len, OPENSSL_SHA_EXT_IMPL);););

    // Aarch64 specific options
    RUN_NEON(MEASURE(sha256(dgst, data, msg_byte_len, OPENSSL_NEON_IMPL);););
    RUN_AARCH64_SHA_EXT(
      MEASURE(sha256(dgst, data, msg_byte_len, SHA_EXT_IMPL);););
    RUN_AARCH64_SHA_EXT(
      MEASURE(sha256(dgst, data, msg_byte_len, OPENSSL_SHA_EXT_IMPL);););

    printf("\n");
  }
}

_INLINE_ void speed_sha512(void)
{
  uint8_t dgst[SHA512_HASH_BYTE_LEN] = {0};
  uint8_t data[MAX_MSG_BYTE_LEN]     = {0};

  // Use a deterministic seed.
  srand(0);
  rand_data(data, sizeof(data));

  printf("\nSHA-512 Benchmark:");
  printf("\n------------------\n");
  printf("        msg     generic");

  // X86-64 specific options
  RUN_X86_64(printf("      avx (C)   avx (ossl)"););
  RUN_AVX2(printf("     avx2 (C)  avx2 (ossl)"););
  RUN_AVX512(printf("   avx512 (C)"););

  // Aarch64 specific options
  RUN_NEON(printf("  neon (ossl)"););

  printf("\n");

  for(size_t msg_byte_len = 1; msg_byte_len <= MAX_MSG_BYTE_LEN;
      msg_byte_len <<= 1) {

    printf("%5ld bytes", msg_byte_len);
    MEASURE(sha512(dgst, data, msg_byte_len, GENERIC_IMPL););

    // X86-64 specific options
    RUN_X86_64(MEASURE(sha512(dgst, data, msg_byte_len, AVX_IMPL);););
    RUN_X86_64(MEASURE(sha512(dgst, data, msg_byte_len, OPENSSL_AVX_IMPL);););
    RUN_AVX2(MEASURE(sha512(dgst, data, msg_byte_len, AVX2_IMPL);););
    RUN_AVX2(MEASURE(sha512(dgst, data, msg_byte_len, OPENSSL_AVX2_IMPL);););
    RUN_AVX512(MEASURE(sha512(dgst, data, msg_byte_len, AVX512_IMPL);););

    // Aarch64 specific options
    RUN_NEON(MEASURE(sha512(dgst, data, msg_byte_len, OPENSSL_NEON_IMPL);););

    printf("\n");
  }
}

int main(void)
{
  speed_sha256();
  speed_sha512();

  return 0;
}
