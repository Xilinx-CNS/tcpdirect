/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * Useful functions for calculating mean, media, percentile and variance
 * Includes write to file and get stats functions for easy use
 */
#include "zf_stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

static int qsort_compare_int(const void* pa, const void* pb)
{
  const int* a = pa;
  const int* b = pb;
  return *a - *b;
}

static inline uint64_t get_mean(const uint64_t* array, size_t len)
{
  uint64_t sum = 0;
  int i = 0;
  for( i = 0; i < len; i++ )
    sum += array[i];
  return (uint64_t) (sum / len);
}

static inline uint64_t get_variance(const uint64_t* array, size_t len,
                                    uint64_t mean)
{
  uint64_t sumsq;
  int64_t diff;
  int i;

  if( len < 2 )
    return 0;

  sumsq = 0;
  for( i = 0; i < len; i++ ) {
    diff = array[i] - mean;
    sumsq += diff * diff;
  }
 return sumsq / (len - 1);
}

void get_stats(struct stats* s, bool halve_values, uint64_t* array,
               size_t len, float percentile)
{
  int i = 0;
  if( halve_values ) {
    for( i = 0; i < len; i++ ) {
      array[i] = array[i] / 2;
    }
  }

  qsort(array, len, sizeof(*array), &qsort_compare_int);
  // sorted array
  s->min = array[0];
  s->max = array[len - 1];
  s->median = array[len >> 1u];
  s->percentile = array[(int) (len * percentile / 100)];

  s->mean = get_mean(array, len);
  uint64_t variance = get_variance(array, len, s->mean);
  s->stddev = (uint64_t) sqrt(variance);
}

void write_raw_array(const char* raw_filename, const uint64_t* array, 
                     size_t len)
{
  FILE* f;
  int i = 0;

  if( (f = fopen(raw_filename, "w")) == NULL ) {
    fprintf(stderr, "ERROR: Could not open output file '%s'\n", raw_filename);
    exit(2);
  }
  for( i = 0; i < len; i++ )
    fprintf(f, "%ld\n", array[i]);

  fclose(f);
}
