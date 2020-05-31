// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <immintrin.h>

int main(void)
{
  __m128i a = _mm_setzero_si128();
  _mm_sha256msg1_epu32(a, a);
}
