/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** \file RX table structures. */


/* These structures are opaque to external users of the RX table, but we stick
 * them in a header file for convenience of unit-testing.  There is no #ifdef
 * inclusion guard as this file should never be included from another header.
 */


#include <zf_internal/rx_table.h>

/* Slow-path RX-table state. */

struct zf_rx_table_entry_res {
  /* Link in list of all of this zocket's table entries. */
  ci_dllink zocket_link;

  /* Number of routes in the hash table passing through this entry.  Includes
   * the route terminating at the entry itself.  Only ever zero if the entry is
   * free, but free entries will still have non-zero route counts when they are
   * tombstones. */
  uint16_t route_count;

  /* Arbitrary data associated with this table entry.  Typically a hardware
   * filter cookie. */
  void* opaque;
};

struct zf_rx_table_res {
  unsigned max_entries;
  unsigned num_entries;

  /* The table itself. */
  struct zf_rx_table* table;

  /* Slow-path per-entry state. */
  struct zf_rx_table_entry_res entry_res[ZF_RX_HASH_TABLE_ENTRIES];
};

