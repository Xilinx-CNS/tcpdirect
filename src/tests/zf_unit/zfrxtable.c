/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Unit test for ZF multiplexer.
**   \date  2016/01/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/rx_table.h>

#include <stdlib.h>

/* The unit test validates the internal structures, so pull them in. */
#include "../../lib/zf/rx_table_structures.h"

#include "../tap/tap.h"


/* Calculates the inverse of n modulo modulus, where modulus is a power of two.
 */
static uint32_t inverse(uint32_t n, uint32_t modulus)
{
  unsigned x, x_next = 1;

  do {
    x = x_next;
    x_next = (x * (2u - n * x)) & (modulus - 1);
  } while( x_next != x );

  return x;
}


/* Walk the hash-table and do some validation.  We don't emit a TAP entry per
 * hash-table entry as this would be a bit noisy. */
static int validate_table(const struct zf_rx_table_res* table_res)
{
  struct zf_rx_table* table = table_res->table;
  unsigned live_entries_found = 0;
  uint64_t total_route_found = 0, total_expected_route = 0;

  for( unsigned i = 0; i < ZF_RX_HASH_TABLE_ENTRIES; ++i ) {
    struct zf_rx_table_entry* entry = &table->hash_table[i];
    const struct zf_rx_table_entry_res* entry_res = &table_res->entry_res[i];

    if( entry_res->route_count > table_res->num_entries ) {
      diag("Route-count %u too high at entry %d (num_entries == %u)",
           entry_res->route_count, i, table_res->num_entries);
      return 0;
    }

    total_route_found += entry_res->route_count;

    if( ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry) ) {
      uint32_t hash1 = zf_rx_table_hash1(entry->laddr_be, entry->raddr_be,
                                         entry->lport_be, entry->rport_be);
      uint32_t hash2 = zf_rx_table_hash2(entry->laddr_be, entry->raddr_be,
                                         entry->lport_be, entry->rport_be);
      ++live_entries_found;
      total_expected_route += (((i - hash1) *
                                inverse(hash2, ZF_RX_HASH_TABLE_ENTRIES)) &
                               ZF_RX_HASH_TABLE_ENTRIES_MASK) + 1;

      if( entry_res->route_count == 0 ) {
        diag("Zero route-count at live entry %d", i);
        return 0;
      }
    }
    else if( ZF_RX_HASH_TABLE_ENTRY_IS_TOMBSTONE(entry) ) {
      /* Nothing to validate here: route count can be arbitrary. */
    }
    else {
      if( entry->zocket_id != ZF_RX_ZOCKET_ID_TERMINAL ) {
        diag("Invalid zocket_index %u at %d", entry->zocket_id, i);
        return 0;
      }

      if( entry_res->route_count != 0 ) {
        diag("Non-zero route-count %u at terminal entry %d",
             entry_res->route_count, i);
        return 0;
      }
    }
  }

  if( live_entries_found != table_res->num_entries ) {
    diag("Found %u live entries, expected %u",
         live_entries_found, table_res->num_entries);
    return 0;
  }

  if( total_expected_route != total_route_found ) {
    diag("Found %u total route, expected %u",
         total_route_found, total_expected_route);
    return 0;
  }

  return 1;
}


/* Ensure that all live entries in the table can be looked up.  This also
 * ensures that there are no duplicate entries. */
static int
validate_all_entries_reachable(const struct zf_rx_table_res* table_res)
{
  struct zf_rx_table* table = table_res->table;

  for( unsigned i = 0; i < ZF_RX_HASH_TABLE_ENTRIES; ++i ) {
    struct zf_rx_table_entry* entry = &table->hash_table[i];

    if( ZF_RX_HASH_TABLE_ENTRY_IS_OCCUPIED(entry) ) {
      uint16_t zocket_id;
      int rc = zf_rx_table_lookup(table, entry->laddr_be, entry->raddr_be,
                                  entry->lport_be, entry->rport_be, &zocket_id);
      if( rc != 0 ) {
        diag("Zocket index %u at entry %u not found by lookup (rc == %d)",
             entry->zocket_id, i, rc);
        abort();
        return 0;
      }

      if( zocket_id != entry->zocket_id ) {
        diag("Zocket lookup expected %u but found %u (duplicate entries?)",
             entry->zocket_id, zocket_id);
        return 0;
      }
    }
  }

  return 1;
}

/* A note on the per-zocket lists of entries as maipulated by zf_rx_table_add()
 * and zf_rx_table_remove(): for these tests we use a single list in all cases,
 * and we don't validate the list contents.  This is covered by the tests for
 * the RX zockets themselves, where the lists actually have some significance.
 */

#define SMALL_TABLE_SIZE   4
#define SMALL_TABLE_TESTS  (SMALL_TABLE_SIZE + 3)

static void test_small_table(struct zf_rx_table_res* small_table_res)
{
  ci_dllist list;
  ci_dllist_init(&list);

  cmp_ok(zf_rx_table_add(small_table_res, 1, 1, 1, 1,
                         ZF_RX_TABLE_MAX_ZOCKET_ID + 1, &list, NULL), "==",
         -EINVAL, "Invalid zocket ID rejected");
  /* Attempt to overflow the small table. */
  uint16_t id = 0;
  for( int i = 0; i < SMALL_TABLE_SIZE; ++i )
    cmp_ok(zf_rx_table_add(small_table_res, i, 0, 0, 0, id++, &list, NULL),
           "==", 0, "Adding entry to small table");
  cmp_ok(zf_rx_table_add(small_table_res, 1, 1, 1, 1, id++, &list, NULL), "==",
         -ENOSPC, "Attempt to overflow small table rejected");
  ok(validate_table(small_table_res), "Small table still valid");
}


#define BIG_TABLE_SIZE   (ZF_RX_TABLE_MAX_ZOCKET_ID + 1)
#define BIG_TABLE_TESTS  18

static void test_big_table(struct zf_rx_table_res* big_table_res)
{
  uint16_t id = 0, id_dummy;
  ci_dllist list;

  ci_dllist_init(&list);

  /* Populate the big table.  We choose parameters that are definitely unique
   * but that are likely to cause collisions. */

#define BIG_TABLE_PARAMS(i)  (i) >> 12, (i) >> 8, ((i) & 0x00f0) >> 4, \
                             (i) & 0x000f
#define BIG_TABLE_OTHER      1 << 4, 0, 0, 0


  for( int i = 0; i < BIG_TABLE_SIZE; ++i )
    zf_rx_table_add(big_table_res, BIG_TABLE_PARAMS(i), id++, &list, NULL);
  cmp_ok(big_table_res->num_entries, "==", BIG_TABLE_SIZE,
         "Populated big table successfully");
  ok(validate_table(big_table_res), "Big table valid after population");
  ok(validate_all_entries_reachable(big_table_res),
     "All entries reachable in big table after population");

  /* We shouldn't be able to add anything more. */
  cmp_ok(zf_rx_table_add(big_table_res, BIG_TABLE_OTHER, 0, &list, NULL), "==",
         -ENOSPC, "Attempt to overflow big table rejected");

  /* Try to look up something not in the table. */
  cmp_ok(zf_rx_table_lookup(big_table_res->table, BIG_TABLE_OTHER, &id_dummy),
         "==", -ENOENT, "Non-existent entry not found");

  /* Remove the thing we first though of. */
  cmp_ok(zf_rx_table_remove(big_table_res, BIG_TABLE_PARAMS(0), NULL), "==", 0,
         "Removed entry");

  /* The new entry should fit now. */
  cmp_ok(zf_rx_table_add(big_table_res, BIG_TABLE_OTHER, 0, &list, NULL), "==",
         0, "Can add once more");

  /* Restore the status quo ante. */
  cmp_ok(zf_rx_table_remove(big_table_res, BIG_TABLE_OTHER, NULL), "==", 0,
         "Removed new entry");
  cmp_ok(zf_rx_table_add(big_table_res, BIG_TABLE_PARAMS(0), 0, &list, NULL),
         "==", 0, "Restored original entry");

  /* Remove all the entries from the table.  Do so in the same order in which
   * they were added to test tombstones, checking validity midway. */
  for( int i = 0; i < BIG_TABLE_SIZE >> 1; ++i )
    zf_rx_table_remove(big_table_res, BIG_TABLE_PARAMS(i), NULL);
  cmp_ok(big_table_res->num_entries, "==",
         BIG_TABLE_SIZE - (BIG_TABLE_SIZE >> 1), "Big table half-emptied");
  ok(validate_table(big_table_res), "Half-empty big table valid");
  ok(validate_all_entries_reachable(big_table_res),
     "All entries reachable in half-empty big table");

  for( int i = BIG_TABLE_SIZE >> 1; i < BIG_TABLE_SIZE; ++i )
    zf_rx_table_remove(big_table_res, BIG_TABLE_PARAMS(i), NULL);
  cmp_ok(big_table_res->num_entries, "==", 0, "Big table empty.");
  ok(validate_table(big_table_res), "Empty big table valid");

  /* Fill the table up once more, associating an integer value of 1 with each
   * entry as opaque data. */
  for( int i = 0; i < BIG_TABLE_SIZE; ++i )
    zf_rx_table_add(big_table_res, BIG_TABLE_PARAMS(i), 0, &list, (void*) 1);
  cmp_ok(big_table_res->num_entries, "==", BIG_TABLE_SIZE,
         "Re-populated big table successfully");

  /* Empty it in one go, summing up the opaque data. */
  static int sum = 0;
  auto sum_callback = [] (void* opaque) {sum += (intptr_t) opaque; return 0;};
  zf_rx_table_remove_list(big_table_res, &list, sum_callback);
  cmp_ok(big_table_res->num_entries, "==", 0, "Big table empty.");
  ok(ci_dllist_is_empty(&list), "Entry-list is empty.");
  cmp_ok(sum, "==", BIG_TABLE_SIZE, "Callbacks called for opaque data.");

#undef BIG_TABLE_OTHER
#undef BIG_TABLE_PARAMS
}


/* Fills a table artificially so that it contains a single live entry, and so
 * that all other entries are tombstones.  We also guarantee that
 * NOT_IN_TOMBSTONEY_TABLE is not in the table. */
#define NOT_IN_TOMBSTONEY_TABLE  1, 1, 1, 1
static void make_tombstoney_table(struct zf_rx_table_res* table_res)
{
  struct zf_rx_table* table = table_res->table;

  /* Make every entry a one-route tombstone to begin with. */
  for( unsigned i = 0; i < ZF_RX_HASH_TABLE_ENTRIES; ++i ) {
    struct zf_rx_table_entry* entry = &table->hash_table[i];
    struct zf_rx_table_entry_res* entry_res = &table_res->entry_res[i];
    entry->zocket_id = ZF_RX_ZOCKET_ID_TOMBSTONE;
    entry_res->route_count = 1;
  }

  /* Add an entry for 0:0 => 0:0 in its least favourite slot. */

  uint32_t hash1 = zf_rx_table_hash1(0, 0, 0, 0);
  uint32_t hash2 = zf_rx_table_hash2(0, 0, 0, 0);
  uint32_t hash_index = (hash1 - hash2) & ZF_RX_HASH_TABLE_ENTRIES_MASK;
  struct zf_rx_table_entry* entry = &table->hash_table[hash_index];

  table_res->num_entries = 1;
  entry->raddr_be = entry->laddr_be = 0;
  entry->rport_be = entry->lport_be = 0;
  entry->zocket_id = 0;
  /* Route count is already correct, and nobody cares about the list link. */
}


#define TOMBSTONEY_TABLE_TESTS  4

static void test_tombstoney_table(struct zf_rx_table_res* table_res)
{
  uint16_t id;
  struct zf_rx_table* table = table_res->table;

  ci_dllist list;
  ci_dllist_init(&list);

  /* Make a table with lots of tombstones. */
  make_tombstoney_table(table_res);
  ok(validate_table(table_res), "Tombstoney table valid");
  ok(validate_all_entries_reachable(table_res), "Tombstoney table route");

  /* Look up a non-existent entry.  This should fail with ENOENT as in earlier
   * such tests, but exercises different paths from the non-tombstoney case. */
  cmp_ok(zf_rx_table_lookup(table, NOT_IN_TOMBSTONEY_TABLE, &id),
         "==", -ENOENT, "Non-existent entry not found");

  /* Adding to the table will certainly require reclaiming a tombstone, so
   * make sure this works. */
  /* The new entry should fit now. */
  cmp_ok(zf_rx_table_add(table_res, NOT_IN_TOMBSTONEY_TABLE, 0, &list, NULL),
         "==", 0, "Can reclaim tombstone");
}


/* We stress the table by adding and removing entries at pseudo-random and
 * verifying periodically that the table is valid.  Each iteration of the loop
 * either adds or removes an entry, with the probability of doing each scaled
 * according to the current fill level.
 *     In order to test the non-lazy allocator, we have to ensure that, over
 * the lifetime of the table, we add more than the instantaneous maximum number
 * of entries.  Since at least half of our operations are additions (because we
 * can't remove an entry that we haven't added), we arrange this by iterating
 * more than 2 * TABLE_SIZE times. */

#define STRESS_TABLE_SIZE          (ZF_RX_TABLE_MAX_ZOCKET_ID + 1)
#define STRESS_ITER_COUNT          (85 * STRESS_TABLE_SIZE)
#define STRESS_VALIDATION_PERIOD   STRESS_TABLE_SIZE
#define STRESS_TESTS               (1 + 2 * (STRESS_ITER_COUNT / \
                                             STRESS_VALIDATION_PERIOD))

_Static_assert(STRESS_ITER_COUNT > 2 * STRESS_TABLE_SIZE,
               "Too few iterations to stress allocator");


static inline zf_allocator*
allocator_create(size_t table_size)
{
  size_t allocator_length = ROUND_UP(zf_rx_table_alloc_size(table_size),
                                     ZF_CACHE_LINE_SIZE) +
                            ROUND_UP(sizeof(zf_rx_table_res),
                                     ZF_CACHE_LINE_SIZE);
  auto alloc = (zf_allocator*) malloc(sizeof(zf_allocator) + allocator_length);
  zf_allocator_init(alloc, allocator_length);
  return alloc;
}

static void test_stress(void)
{
  zf_allocator* alloc = allocator_create(STRESS_TABLE_SIZE);
  struct zf_rx_table_res* table_res;
  int rc = zf_rx_table_alloc(alloc, STRESS_TABLE_SIZE, &table_res);
  cmp_ok(rc, "==", 0, "Allocate stress table");

  unsigned seed = 0x5eed5eed;

  /* Keep a record of the entries we've added in a densely-packed array so that
   * we can choose from them at random. */
  struct zf_rx_table_entry pseudo_entries[STRESS_TABLE_SIZE];
  uint16_t id;

  ci_dllist list;
  ci_dllist_init(&list);

  struct zf_rx_table* table = table_res->table;

  for( unsigned i = 0; i < STRESS_ITER_COUNT; ++i ) {
    if( (int64_t) rand_r(&seed) * STRESS_TABLE_SIZE >=
        (int64_t) RAND_MAX * table_res->num_entries ) {
      /* Add. */

      /* Find the external state that we're going to use to track the added
       * entry. */
      struct zf_rx_table_entry* pe = &pseudo_entries[table_res->num_entries];

      int retry_count = 0;
      do {
        /* RAND_MAX is large enough that this is extremely unlikely. */
        if( ++retry_count > 5 )
          BAIL_OUT("Too many retries finding entry to add");

        /* Generate an entry to add and make sure it's not a duplicate. */
        pe->laddr_be = (uint32_t) rand_r(&seed);
        pe->raddr_be = (uint32_t) rand_r(&seed);
        pe->lport_be = (uint16_t) rand_r(&seed);
        pe->rport_be = (uint16_t) rand_r(&seed);
      } while( zf_rx_table_lookup(table, pe->laddr_be, pe->raddr_be,
                                  pe->lport_be, pe->rport_be, &id) != -ENOENT );

      rc = zf_rx_table_add(table_res, pe->laddr_be, pe->raddr_be, pe->lport_be,
                           pe->rport_be, 0, &list, NULL);
      if( rc != 0 )
        BAIL_OUT("Failed to add entry (rc == %d)", rc);
    }
    else {
      /* Remove. */
      int index = rand_r(&seed) % table_res->num_entries;
      struct zf_rx_table_entry* pe = &pseudo_entries[index];
      rc = zf_rx_table_remove(table_res, pe->laddr_be, pe->raddr_be,
                              pe->lport_be, pe->rport_be, NULL);
      if( rc != 0 )
        BAIL_OUT("Failed to remove entry (rc == %d)", rc);

      /* Repack the array. */
      if( table_res->num_entries > 0 )
        *pe = pseudo_entries[table_res->num_entries];
    }

    if( (i + 1) % STRESS_VALIDATION_PERIOD == 0 ) {
      ok(validate_table(table_res), "Table valid after %u iterations", i);
      ok(validate_all_entries_reachable(table_res),
         "Table routes valid after %u iterations", i);
    }
  }

  __zf_rx_table_free(alloc, table_res);
  free(alloc);
}


#define INLINE_TESTS 5

int main(void)
{
  int rc;

  plan(INLINE_TESTS + SMALL_TABLE_TESTS + BIG_TABLE_TESTS +
       TOMBSTONEY_TABLE_TESTS + STRESS_TESTS);

  zf_allocator* small_alloc = allocator_create(SMALL_TABLE_SIZE);
  /* Allocate a small table. */
  struct zf_rx_table_res* small_table_res;
  rc = zf_rx_table_alloc(small_alloc, SMALL_TABLE_SIZE, &small_table_res);
  cmp_ok(rc, "==", 0, "Alloc small table");
  ok(validate_table(small_table_res), "Small table valid");

  zf_allocator* big_alloc = allocator_create(ZF_RX_TABLE_MAX_ZOCKET_ID + 2);

  /* Allocate a big table.  Try to make it too big first. */
  struct zf_rx_table_res* big_table_res;
  rc = zf_rx_table_alloc(big_alloc, ZF_RX_TABLE_MAX_ZOCKET_ID + 2, &big_table_res);
  cmp_ok(rc, "==", -EINVAL, "Attempt to allocate too-large table rejected");

  rc = zf_rx_table_alloc(big_alloc, BIG_TABLE_SIZE, &big_table_res);
  cmp_ok(rc, "==", 0, "Alloc big table");
  ok(validate_table(big_table_res), "Big table valid");

  /* Run some directed addition/removal/lookup tests on each table. */
  test_small_table(small_table_res);
  test_big_table(big_table_res);
  test_tombstoney_table(big_table_res);

  __zf_rx_table_free(small_alloc, small_table_res);
  free(small_alloc);
  __zf_rx_table_free(big_alloc, big_table_res);
  free(big_alloc);

  /* Run a stress test that performs many additions and removals, with
   * validity checks. */
  test_stress();

  done_testing();

  return 0;
}

