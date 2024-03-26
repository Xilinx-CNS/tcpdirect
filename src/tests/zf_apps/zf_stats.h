/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * Useful functions for calculating mean, media, percentile and variance
 * Includes write to file and get stats functions for easy use
 */

#ifndef ZF_APPS_STATS_H
#define ZF_APPS_STATS_H

#include <stdbool.h>
#include <stdint.h>

struct stats {
  uint64_t mean;
  uint64_t min;
  uint64_t median;
  uint64_t max;
  uint64_t percentile;
  uint64_t stddev;
};

/* Given an array it will write to the stats struct with mean, median, min, max, percentile, 
 * and standard deviation for it. 
 * @stats Struct in which stats results about array will be returned
 * @halve_values: halves array values before calculating stats for use cases such as half or full rtt
 * @array Input array for which stats needs to be calculated
 * @len Length of the input array
 * @percentile: identifies the k-th percentile to report in stats 
 */
void get_stats(struct stats* s, bool halve_values, uint64_t* array, uint64_t len, float percentile);

/* Prints the array in given file with each value on single line. 
 * @raw_filename File name to which array needs to be printed out.
 * @array Array to printed to file
 * @len Length of the array to be printed
 */
void write_raw_array(const char* raw_filename,
                     const uint64_t* array, uint64_t len);

#endif /* ZF_APPS_STATS_H */
