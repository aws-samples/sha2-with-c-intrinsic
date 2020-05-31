// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <immintrin.h>

int main(void)
{
  __m512i reg;
  uint64_t mem[8];
  reg = _mm512_loadu_si512((const __m512i*)mem);
  _mm512_storeu_si512((__m512i*)mem, reg);
}
