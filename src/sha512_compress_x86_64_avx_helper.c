// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// An implementation of the compress function of SHA512 using avx/avx2/avx512
// It was translated from assembly (OpenSSL) to C by
//
// Nir Drucker and Shay Gueron
// AWS Cryptographic Algorithms Group.
// (ndrucker@amazon.com, gueron@amazon.com)

// This file depends on vec_t and on the following macros:
// LOAD, ADD64, ALIGNR8, SRL64, SLL64

#define SHA512_WORD_BIT_LEN (8 * sizeof(sha512_word_t))

_INLINE_ void rotate_x(vec_t x[8])
{
  const vec_t tmp = x[0];

  for(size_t i = 0; i < 7; i++) {
    x[i] = x[i + 1];
  }

  x[7] = tmp;
}

#ifndef ALTERNATIVE_AVX512_IMPL

_INLINE_ vec_t sha512_update_x_avx(vec_t x[8], const sha512_word_t *K512_p)
{
  vec_t t[4];

  // This function recieves 8 128-bit registers X[7:0]=q[15:0] and calculates:
  // s0 = sigma0(q[(i + 1) % 16])
  // s1 = sigma1(q[(i + 14) % 16])
  // q[i % 16] += s0 + s1 + q[(i + 9) % 16]
  //
  // For X[0]=q[3:0]
  //
  // This means that
  // res[0] depends on q[1] (for s0) q[14] (for s1) and q[9]
  // res[1] depends on q[2] (for s0) q[15] (for s1) and q[10]
  // res[2] depends on q[3] (for s0) res[0] (for s1) and q[11]
  // res[3] depends on q[4] (for s0) res[1] (for s1) and q[12]

  t[0] = ALIGNR8(x[1], x[0], 8);                      // q[2:1]
  t[3] = ALIGNR8(x[5], x[4], 8);                      // q[10:9]
  t[2] = SRL64(t[0], sigma0_0);                       // q[2:1] >> s0[0]
  x[0] = ADD64(x[0], t[3]);                           // q[1:0] + q[10:9]
  t[3] = SRL64(t[0], sigma0_2);                       // q[2:1] >> s0[2]
  t[1] = SLL64(t[0], SHA512_WORD_BIT_LEN - sigma0_1); // q[2:1] << (64 - s0[1])
  t[0] = t[3] ^ t[2];                                 // (q[2:1] >> s0[2]) ^
                                                      //   (q[2:1] >> s0[0])
  t[2] = SRL64(t[2], sigma0_1 - sigma0_0);            // q[2:1] >> s0[1]
  t[0] ^= t[1];                                       // (q[2:1] >> s0[2]) ^
                                                      //  (q[2:1] >> s0[0]) ^
                                                      //  q[2:1] << (64 - s0[1])
  t[1] = SLL64(t[1], sigma0_1 - sigma0_0);            // q[2:1] << (64 - s0[0])
  t[0] ^= t[2] ^ t[1];                                // sigma1(q[2:1])
  t[3] = SRL64(x[7], sigma1_2);                       // q[15:14] >> s1[2]
  t[2] = SLL64(x[7], SHA512_WORD_BIT_LEN - sigma1_1); // q[15:14] >> (64 - s1[1])
  x[0] = ADD64(x[0], t[0]);                           // q[1:0] + sigma0(q[2:1])
  t[1] = SRL64(x[7], sigma1_0);                       // q[15:14] >> s1[0]
  t[3] ^= t[2];                                       // q[15:14] >> s1[2] ^
                                                      //  q[15:14] >> (64 - s1[1])
  t[2] = SLL64(t[2], sigma1_1 - sigma1_0);            // q[15:14] >> (64 - s1[0])
  t[3] ^= t[1];                                       // q[15:14] >> s1[2] ^
                //  q[15:14] >> (64 - s1[1] ^
                //  q[15:14] >> s1[0]
  t[1] = SRL64(t[1], sigma1_1 - sigma1_0); // q[15:14] >> s1[1]
  t[3] ^= t[2] ^ t[1];                     // sigma1(q[15:14])

  // q[1:0] + q[10:9] + sigma1(q[15:14]) + sigma0(q[2:1])
  x[0] = ADD64(x[0], t[3]);

  rotate_x(x);

  return ADD64(x[7], LOAD(K512_p));
}

#else

_INLINE_ vec_t sha512_update_x_avx(vec_t x[8], const sha512_word_t *k512_p)
{
  vec_t t[2];
  vec_t s0;
  vec_t s1;

  // This function recieves 8 wide registers X[7:0]=q[15:0] and calculates:
  // s0 = sigma0(q[2:1])
  // s1 = sigma1(q[15:14])
  // q[1:0] += s0 + s1 + q[10:9]

  t[0] = ALIGNR8(x[1], x[0], 8); // q[2:1]
  t[1] = ALIGNR8(x[5], x[4], 8); // q[10:9]
  s0   = ROR64(t[0], sigma0_0) ^ ROR64(t[0], sigma0_1) ^ SRL64(t[0], sigma0_2);
  s1   = ROR64(x[7], sigma1_0) ^ ROR64(x[7], sigma1_1) ^ SRL64(x[7], sigma1_2);
  x[0] = ADD64(ADD64(ADD64(x[0], s1), s0), t[1]);

  rotate_x(x);

  return ADD64(x[7], LOAD(k512_p));
}

#endif
