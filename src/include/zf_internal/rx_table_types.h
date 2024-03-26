/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_RX_TABLE_TYPES_H__
#define __ZF_INTERNAL_RX_TABLE_TYPES_H__


#include <stdint.h>

#include <zf_internal/utils.h>

/* Restrictions:
 *  - No more than (64K - 2) entries are allowed per table.  This allows us
 *    to do two things:
 *      * store route-counts in 16 bits; and
 *      * reserve a couple of indices for special purposes.
 *    Note that this also imposes the same upper bound on the number of RX
 *    zockets (as opposed to entries) per table.
 */


#define ZF_RX_TABLE_MAX_ENTRIES    (UINT16_MAX - 1)
#define ZF_RX_ZOCKET_ID_TOMBSTONE  (UINT16_MAX - 1)
#define ZF_RX_ZOCKET_ID_TERMINAL   UINT16_MAX
#define ZF_RX_TABLE_MAX_ZOCKET_ID  (ZF_RX_TABLE_MAX_ENTRIES - 1)


/* Fast-path RX-table state. */
struct zf_rx_table_entry {
  uint32_t laddr_be, raddr_be;
  uint16_t lport_be, rport_be;

  /* Index into the array of zockets, or else one of the special
   * ZF_RX_ZOCKET_ID_x values. */
  uint16_t zocket_id;
};

#define ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry) \
  ((entry)->zocket_id <= ZF_RX_TABLE_MAX_ZOCKET_ID)
#define ZF_RX_HASH_TABLE_ENTRY_IS_TOMBSTONE(entry) \
  ((entry)->zocket_id == ZF_RX_ZOCKET_ID_TOMBSTONE)


/* With a perfect hashing function, this gives a probability of collisions in
 * the hash table of less than 2% with 64 zockets.  It also makes the table fit
 * exactly into an x86_64 huge page. */
#define ZF_RX_HASH_TABLE_ENTRIES_SHIFT  17
#define ZF_RX_HASH_TABLE_ENTRIES        (1u << ZF_RX_HASH_TABLE_ENTRIES_SHIFT)
#define ZF_RX_HASH_TABLE_ENTRIES_MASK   (ZF_RX_HASH_TABLE_ENTRIES - 1)

/* We want to ensure that, by iterating n, hash1 + n * hash2 iterates over the
 * entire table.  This is equivalent to ensuring that hash2 is always coprime
 * to the size of the table.  We achieve this by making the table power-of-two-
 * sized and ensuring that hash2 is odd. */
_Static_assert(ZF_IS_POW2(ZF_RX_HASH_TABLE_ENTRIES),
               "RX hash table is not power-of-two-sized.");

/* We also require that we never fill the hash table, in order to avoid
 * handling special cases. */
_Static_assert(ZF_RX_HASH_TABLE_ENTRIES > ZF_RX_TABLE_MAX_ENTRIES,
               "RX hash table is too small.");

struct zf_rx_table {
  struct zf_rx_table_entry hash_table[ZF_RX_HASH_TABLE_ENTRIES];
};

struct zf_rx_table_res;


#endif /* __ZF_INTERNAL_RX_TABLE_TYPES_H__ */

