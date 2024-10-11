/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect stats API
*//*
\**************************************************************************/

#ifndef __ZF_STATS_H__
#define __ZF_STATS_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif

#include <etherfabric/vi.h>

typedef ef_vi_stats_field_layout zf_stats_field_layout;
typedef ef_vi_stats_layout zf_stats_layout;

/*! \brief  */
typedef struct {
  /** Number of underlying interfaces present in stack */
  int               num_intfs;
  /** Size of memory needed to query the stats in bytes */
  int               total_data_size;
  /** Array of layouts, one per interface */
  zf_stats_layout** layout;
} zf_layout_collection;

/*! \brief Allocate and retrieve layout for available statistics
**
** \param stack      The stack to query.
** \param collection Pointer to an zf_layout_collection, that is allocated and
**                   updated on return with the layout for available
**                   statistics. This must be released when no longer needed
**                   using zf_stats_free_layout_collection().
**
** \return Zero on success or negative error code.
**
** Retrieve layout for available statistics.
*/
ZF_LIBENTRY int
zf_stats_alloc_layout_collection(struct zf_stack* stack,
                                 zf_layout_collection** collection);

/*! \brief Release the layout allocated by zf_stats_alloc_query_layout().
**
** \param collection Pointer to an zf_layout_collection that was allocated
**                   using zf_stats_alloc_layout_collection().
*/
ZF_LIBENTRY void
zf_stats_free_layout_collection(zf_layout_collection* collection);

/*! \brief Retrieve a set of statistic values
**
** \param stack      The stack to query.
** \param data       Pointer to a buffer, into which the statistics are
**                   retrieved.
**                   The size of this buffer must be equal to the value of
**                   total_data_size in the zf_layout_collection structure.
** \param collection Pointer to a zf_layout_collection, that was allocated for
**                   this stack by zf_stats_alloc_layout_collection.
** \param do_reset   True to reset the statistics after retrieving them.
**
** \return zero or a negative error code.
**
** Retrieve a set of statistic values.
**
** If do_reset is true, the statistics are reset after reading.
*/
ZF_LIBENTRY int zf_stats_query(struct zf_stack* stack, void* data,
                               zf_layout_collection* collection,
                               int do_reset);

#endif /* __ZF_STATS_H__ */
/** @} */