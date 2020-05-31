// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <immintrin.h>

int main(void)
{
  __m256i reg;
  uint64_t mem[4];
  reg = _mm256_loadu_si256((const __m256i*)mem);
  _mm256_storeu_si256((__m256i*)mem, reg);
}
