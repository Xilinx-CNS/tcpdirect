/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** RX lookup table. */


#include <stdlib.h>
#include <errno.h>

#include <zf_internal/rx_table.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_stackdump.h>

#include "rx_table_structures.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


static void
zf_rx_table_init(struct zf_rx_table_res* table_res, unsigned max_entries)
{
  struct zf_rx_table* table = table_res->table;

  table_res->max_entries = max_entries;
  table_res->num_entries = 0;

  for( unsigned i = 0; i < ZF_RX_HASH_TABLE_ENTRIES; ++i ) {
    table->hash_table[i].zocket_id = ZF_RX_ZOCKET_ID_TERMINAL;
    table_res->entry_res[i].route_count = 0;
    ci_dllink_self_link(&table_res->entry_res[i].zocket_link);
  }
}


int zf_rx_table_alloc(zf_allocator* a, unsigned max_entries,
                      struct zf_rx_table_res** table_res_out)
{
  if( max_entries > ZF_RX_TABLE_MAX_ENTRIES )
    return -EINVAL;

  auto table_res = (zf_rx_table_res*)
                   zf_allocator_alloc(a, sizeof(zf_rx_table_res));
  if( table_res == NULL )
    goto fail1;

  /* TODO: We should allocate this in a more sophisticated way.
   * Depending on max_etnries? */
  table_res->table = (typeof(table_res->table))
                     zf_allocator_alloc(a,
                                   zf_rx_table_alloc_size(max_entries));
  if( table_res->table == NULL )
    goto fail2;

  zf_rx_table_init(table_res, max_entries);

  *table_res_out = table_res;

  return 0;

fail2:
  zf_allocator_free(a, table_res);
fail1:
  return -ENOMEM;
}


size_t zf_rx_table_alloc_size(unsigned max_entries)
{
  return sizeof(zf_rx_table);
}


/* Frees an RX table. */
void zf_rx_table_free(zf_allocator* a, struct zf_rx_table_res* table_res)
{
  if( table_res != NULL ) {
    zf_assert_equal(table_res->num_entries, 0);
    zf_allocator_free(a, table_res->table);
    zf_allocator_free(a, table_res);
  }
}

/* Frees an RX table.  We don't require that it be empty.
 * To be used from the unit tests. */
void __zf_rx_table_free(zf_allocator* a, struct zf_rx_table_res* table_res)
{
  if( table_res != NULL ) {
    zf_allocator_free(a, table_res->table);
    zf_allocator_free(a, table_res);
  }
}


struct zf_rx_table* zf_rx_table_get(struct zf_rx_table_res* table_res)
{
  return table_res->table;
}


/* Adds a new entry to the RX-lookup table.  An entry for the address quadruple
 * must not exist already in the table.  The pointer [opaque] is stored along
 * with the entry and can be whatever the caller likes.  The envisaged usage is
 * to store references to hardware state (i.e. to filters in the form of an
 * [ef_filter_cookie]) that correspond to table entries.
 */
int
zf_rx_table_add(struct zf_rx_table_res* table_res, uint32_t laddr_be,
                uint32_t raddr_be, uint16_t lport_be, uint16_t rport_be,
                uint16_t zocket_id, ci_dllist* zocket_entry_list, void* opaque)
{
  struct zf_rx_table* table = table_res->table;
  uint32_t first_index, index;

  if( table_res->num_entries >= table_res->max_entries )
    return -ENOSPC;
  if( zocket_id > ZF_RX_TABLE_MAX_ZOCKET_ID )
    return -EINVAL;

  first_index = zf_rx_table_hash1(laddr_be, raddr_be, lport_be, rport_be) &
                ZF_RX_HASH_TABLE_ENTRIES_MASK;
  index = first_index;

  do {
    struct zf_rx_table_entry* entry = &table->hash_table[index];
    struct zf_rx_table_entry_res* entry_res = &table_res->entry_res[index];

    /* Increment the route count now, as it includes the count for the entry
     * itself. */
    ++entry_res->route_count;

    if( ! ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry) ) {
      /* This entry is free, so we claim it for our new zocket. */
      ++table_res->num_entries;

      entry->laddr_be = laddr_be;
      entry->raddr_be = raddr_be;
      entry->lport_be = lport_be;
      entry->rport_be = rport_be;
      entry->zocket_id = zocket_id;

      entry_res->opaque = opaque;
      zf_assert(ci_dllink_is_self_linked(&entry_res->zocket_link));
      ci_dllist_push(zocket_entry_list, &entry_res->zocket_link);

      return 0;
    }

    /* This entry was not free, so it's at least on our route and on its own.
     */
    zf_assert_ge(entry_res->route_count, 2);

    /* Adding a duplicate entry is illegal, so we should never get a match
     * here.  If we bail out at this point, though, we'll corrupt the table
     * even more seriously, so in release builds we don't bother checking. */
#ifndef NDEBUG
    if( zf_rx_table_entry_matches(entry, laddr_be, raddr_be, lport_be,
                                  rport_be) ) {
      zf_assert(0);
      return -EEXIST;
    }
#endif

    index += zf_rx_table_hash2(laddr_be, raddr_be, lport_be, rport_be);
    index &= ZF_RX_HASH_TABLE_ENTRIES_MASK;
  } while( index != first_index );

  /* We never fill the hash table completely, so we will never get here. */
  zf_assert(0);
  ZF_UNREACHABLE();

  return -ELOOP;
}


/* Removes an RX entry from the hash table.  It must exist. */
int zf_rx_table_remove(struct zf_rx_table_res* table_res, uint32_t laddr_be,
                       uint32_t raddr_be, uint16_t lport_be, uint16_t rport_be,
                       void** opaque_out)
{
  struct zf_rx_table* table = table_res->table;
  uint32_t first_index, index;

  first_index = zf_rx_table_hash1(laddr_be, raddr_be, lport_be, rport_be) &
                ZF_RX_HASH_TABLE_ENTRIES_MASK;
  index = first_index;

  do {
    struct zf_rx_table_entry* entry = &table->hash_table[index];
    struct zf_rx_table_entry_res* entry_res = &table_res->entry_res[index];

    zf_assert_gt(entry_res->route_count, 0);
    --entry_res->route_count;

    if( ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry) &&
        zf_rx_table_entry_matches(entry, laddr_be, raddr_be, lport_be,
                                  rport_be) ) {
      /* Found it. Remove it from the table and the zocket-ownership list. */
      ci_dllist_remove_safe(&entry_res->zocket_link);
      if( opaque_out != NULL )
        *opaque_out = entry_res->opaque;
      entry->zocket_id =
        entry_res->route_count == 0 ? ZF_RX_ZOCKET_ID_TERMINAL :
                                      ZF_RX_ZOCKET_ID_TOMBSTONE;
      --table_res->num_entries;
      return 0;
    }

    index += zf_rx_table_hash2(laddr_be, raddr_be, lport_be, rport_be);
    index &= ZF_RX_HASH_TABLE_ENTRIES_MASK;
  } while( index != first_index );

  /* Attempting to free a nonexistent entry will end up here (if we don't trip
   * the assertion in the loop first).  We've corrupted the hash table by
   * decrementing every entry's route count. */
  zf_assert(0);

  return -ENOENT;
}

#define ENTRY_RES_INDEX(table_res, _entry_res) \
  ((_entry_res) - (table_res)->entry_res)

/* Removes all RX-table entries for a zocket from the table.  opaque_callback()
 * is called with the opaque data for each of the entries removed. */
int zf_rx_table_remove_list(struct zf_rx_table_res* table_res,
                            ci_dllist* zocket_entry_list,
                            int (*opaque_callback)(void* opaque))
{

  struct zf_rx_table_entry_res* entry_res;
  struct zf_rx_table_entry_res* next_entry_res;

  CI_DLLIST_FOR_EACH3(struct zf_rx_table_entry_res, entry_res, zocket_link,
                      zocket_entry_list, next_entry_res) {
    void* opaque;
    int rc;
    struct zf_rx_table_entry* entry =
      &table_res->table->hash_table[ENTRY_RES_INDEX(table_res, entry_res)];

    /* This entry must currently be occupied. */
    zf_assert(ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry));

    /* Remove the entry from the table. */
    rc = zf_rx_table_remove(table_res, entry->laddr_be, entry->raddr_be,
                            entry->lport_be, entry->rport_be, &opaque);
    zf_assert_equal(rc, 0);

    /* Let the caller do something with the opaque data.  This will typically
     * involve such things as removing filters and closing backing sockets. */
    if( opaque_callback != NULL ) {
      rc = opaque_callback(opaque);
      if( rc < 0 )
        return rc;
    }
  }

  return 0;
}


void zf_rx_table_dump_list(SkewPointer<zf_rx_table_res> table_res,
                           SkewPointer<ci_dllist> zocket_entry_list)
{
  struct zf_rx_table_entry_res* entry_res;
  struct zf_rx_table_entry* hash_table =
    table_res.adjust_pointer(table_res->table)->hash_table;

  CI_DLLIST_FOR_EACH2(struct zf_rx_table_entry_res, entry_res, zocket_link,
                      zocket_entry_list) {
    /* The iteration macro almost works correctly if we adjust the pointer that
     * it gives us.  The 'almost' is that the termination check doesn't work,
     * so we do that ourselves. */
    entry_res = zocket_entry_list.adjust_pointer(entry_res);
    if( &entry_res->zocket_link == ci_dllist_end(zocket_entry_list) )
      break;

    ptrdiff_t entry_index = ENTRY_RES_INDEX(table_res, entry_res);
    struct zf_rx_table_entry* entry = hash_table + entry_index;

    /* This entry must currently be occupied. */
    zf_assert(ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry));

    ZF_INET_NTOP_DECLARE_BUF(lbuf);
    ZF_INET_NTOP_DECLARE_BUF(rbuf);

    zf_dump("  filter: lcl=%s:%u rmt=%s:%u\n",
            ZF_INET_NTOP_CALL(entry->laddr_be, lbuf), ntohs(entry->lport_be),
            ZF_INET_NTOP_CALL(entry->raddr_be, rbuf), ntohs(entry->rport_be));
  }
}
