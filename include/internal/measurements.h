// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <float.h>
#include <stdint.h>

#ifndef REPEAT
#  define REPEAT 100
#endif

#ifndef OUTER_REPEAT
#  define OUTER_REPEAT 10
#endif

#ifndef WARMUP
#  define WARMUP (REPEAT / 4)
#endif

uint64_t start_clk, end_clk;
double   total_clk;
double   temp_clk;
size_t   rdtsc_itr;
size_t   rdtsc_outer_itr;

#define HALF_GPR_SIZE UINT8_C(32)

#if defined(X86_64)
inline static uint64_t get_Clks(void)
{
  uint64_t hi;
  uint64_t lo;
  __asm__ __volatile__("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
  return lo ^ (hi << HALF_GPR_SIZE);
}
#endif

#if defined(AARCH64)
inline static uint64_t get_Clks(void)
{
  /*uint32_t hi;
  uint32_t lo;
  __asm__ __volatile__("rdtscp\n\t" : "=a"(lo), "=d"(hi)::"rcx");
  return ((uint64_t)lo) ^ (((uint64_t)hi) << HALF_GPR_SIZE);*/
  uint64_t value;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
  return value;
}
#endif

// This MACRO measures the number of cycles "x" runs. This is the flow:
//   1) it repeats "x" WARMUP times, in order to warm the cache.
//   2) it reads the Time Stamp Counter at the beginning of the test.
//   3) it repeats "x" REPEAT number of times.
//   4) it reads the Time Stamp Counter again at the end of the test
//   5) it calculates the average number of cycles per one iteration of "x", by
//      calculating the total number of cycles, and dividing it by REPEAT
#define RDTSC_MEASURE(x)                                                        \
  for(rdtsc_itr = 0; rdtsc_itr < WARMUP; rdtsc_itr++) {                         \
    {x};                                                                        \
  }                                                                             \
  total_clk = DBL_MAX;                                                          \
  for(rdtsc_outer_itr = 0; rdtsc_outer_itr < OUTER_REPEAT; rdtsc_outer_itr++) { \
    start_clk = get_Clks();                                                     \
    for(rdtsc_itr = 0; rdtsc_itr < REPEAT; rdtsc_itr++) {                       \
      {x};                                                                      \
    }                                                                           \
    end_clk  = get_Clks();                                                      \
    temp_clk = (double)(end_clk - start_clk) / REPEAT;                          \
    if(total_clk > temp_clk) total_clk = temp_clk;                              \
  }                                                                             \
  printf("%12.0f ", total_clk);

#define MEASURE(x) RDTSC_MEASURE(x)
