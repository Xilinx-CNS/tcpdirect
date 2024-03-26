/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** RX lookup table. */

#ifndef __ZF_INTERNAL_RX_TABLE_H__
#define __ZF_INTERNAL_RX_TABLE_H__


#include <stdint.h>

#include <zf_internal/rx_table_types.h>
#include <zf_internal/utils.h>
#include <zf_internal/allocator.h>
#include <zf_internal/zf_stackdump.h>



/* Despite the analysis above assuming a perfect hash, we use a poor but very
 * fast hash. */

ZF_HOT ZF_CONSTFUNC static inline uint32_t
zf_rx_table_hash1(uint32_t laddr_be, uint32_t raddr_be, uint16_t lport_be,
                  uint16_t rport_be)
{
  (void) raddr_be;
  /* XXX: This shift should only be done on little-endian systems. */
  laddr_be >>= 32 - ZF_RX_HASH_TABLE_ENTRIES_SHIFT;
  return lport_be ^ rport_be ^ laddr_be;
}


ZF_HOT ZF_CONSTFUNC static inline uint32_t
zf_rx_table_hash2(uint32_t laddr_be, uint32_t raddr_be, uint16_t lport_be,
                  uint16_t rport_be)
{
  (void) laddr_be;
  (void) rport_be;
  /* XXX: This shift should only be done on little-endian systems. */
  raddr_be >>= 32 - ZF_RX_HASH_TABLE_ENTRIES_SHIFT;
  return (lport_be ^ raddr_be) | 1;
}


ZF_HOT static inline int
zf_rx_table_entry_matches(const struct zf_rx_table_entry* entry,
                          uint32_t laddr_be, uint32_t raddr_be,
                          uint16_t lport_be, uint16_t rport_be)
{
  return (entry->laddr_be == laddr_be) & (entry->raddr_be == raddr_be) &
         (entry->lport_be == lport_be) & (entry->rport_be == rport_be);
}


/* Looks up an RX structure from the table. */
ZF_HOT static inline int
zf_rx_table_lookup(struct zf_rx_table* table, uint32_t laddr_be,
                   uint32_t raddr_be, uint16_t lport_be, uint16_t rport_be,
                   uint16_t* zocket_id_out)
{
  uint32_t first_index, index;

  first_index = zf_rx_table_hash1(laddr_be, raddr_be, lport_be, rport_be) &
                ZF_RX_HASH_TABLE_ENTRIES_MASK;
  index = first_index;

  do {
    struct zf_rx_table_entry* entry = &table->hash_table[index];

    if( ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry) ) {
      if( zf_rx_table_entry_matches(entry, laddr_be, raddr_be, lport_be,
                                    rport_be) ) {
        *zocket_id_out = entry->zocket_id;
        return 0;
      }
    }
    else if( ! ZF_RX_HASH_TABLE_ENTRY_IS_TOMBSTONE(entry) )
      return -ENOENT;

    index += zf_rx_table_hash2(laddr_be, raddr_be, lport_be, rport_be);
    index &= ZF_RX_HASH_TABLE_ENTRIES_MASK;
  } while( index != first_index );

  /* We can only get here if there are no free non-tombstone entries.  This is
   * vastly unlikely, but possible in principle. */
  return -ENOENT;
}


/* External interface. */

ZF_COLD extern int
zf_rx_table_alloc(zf_allocator* a, unsigned max_entries,
                  struct zf_rx_table_res** table_res_out);

ZF_COLD extern void
zf_rx_table_free(zf_allocator* a, struct zf_rx_table_res*);
ZF_COLD extern void
__zf_rx_table_free(zf_allocator* a, struct zf_rx_table_res*);

ZF_COLD extern size_t
zf_rx_table_alloc_size(unsigned max_entries);

ZF_COLD extern struct zf_rx_table*
zf_rx_table_get(struct zf_rx_table_res* table_res);

ZF_COLD extern int
zf_rx_table_add(struct zf_rx_table_res*, uint32_t laddr_be, uint32_t raddr_be,
                uint16_t lport_be, uint16_t rport_be, uint16_t zocket_id,
                ci_dllist* zocket_entry_list, void* opaque);

ZF_COLD extern int
zf_rx_table_remove(struct zf_rx_table_res*, uint32_t laddr_be,
                   uint32_t raddr_be, uint16_t lport_be, uint16_t rport_be,
                   void** opaque_out);

ZF_COLD extern int
zf_rx_table_remove_list(struct zf_rx_table_res* table_res,
                        ci_dllist* zocket_entry_list,
                        int (*opaque_callback)(void* opaque));

ZF_COLD extern void
zf_rx_table_dump_list(SkewPointer<struct zf_rx_table_res> table_res,
                      SkewPointer<ci_dllist> zocket_entry_list);

#endif /* __ZF_INTERNAL_RX_TABLE_H__ */

