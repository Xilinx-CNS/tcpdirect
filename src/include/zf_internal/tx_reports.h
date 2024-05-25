/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef ZF_INTERNAL_TX_REPORTS_H
#define ZF_INTERNAL_TX_REPORTS_H

#include <zf_internal/stack_params.h>

namespace zf_tx_reports {

static constexpr unsigned zock_count = 2 * (ZF_ZOCKET_ID_MAX + 1);
static constexpr unsigned zock_invalid = 0xff;
static_assert(zock_invalid >= zock_count);

using node_t = uint16_t;
using zock_t = uint8_t;

/* Structure to track the list of reports for a single socket within
 * the combined queue structure. We track the tail for appending new partial
 * reports, the head for reading complete reports in order, and the point up to
 * which we have complete reports */
struct zock {
  node_t head, tail; /* Head and tail of fifo list for this zocket */
  node_t pending;    /* First incomplete report, or zero */
  bool dropped;      /* Indicates that reports have been dropped */
};

/* Wrapper for a report held in the queue.
 *
 * In use, it appears in two lists:
 *   - per-zocket fifo list, for reading in order for that zocket;
 *   - list of all used nodes, to evict the oldest when the queue is full.
 *
 * When not in use, it is held in a free list. zock_next is reused for that.
 */
struct node {
  node_t zock_next;            /* Single list for zocket or free list */
  node_t used_next, used_prev; /* Double list of all used nodes */
  zock_t zock;                 /* Owner of this node */
  zf_pkt_report report;
};

/* Queue structure to hold reports for all zockets in a stack until read by
 * the user. Each zocket has a list of reports to read in order of creation.
 */
struct queue {
  bool enabled() const {return nodes;}
  struct zock zocks[zock_count];
  /* The first node is a dummy, used to find the free and used lists. */
  /* This also means that zero can be regarded as a "null" index */
  struct node* nodes;
};


static inline int alloc_queue(struct queue* q, struct zf_allocator* a, int len)
{
  zf_assert(len == node_t(len));
  len += 1; /* For the dummy first node */

  void* nodes = zf_allocator_alloc(a, len * sizeof(struct node));
  if( ! nodes )
    return -ENOMEM;

  q->nodes = static_cast<struct node*>(nodes);
  for( int i = 0; i < len; ++i ) {
    q->nodes[i].zock = zock_invalid;
    q->nodes[i].zock_next = i + 1;
  }
  q->nodes[len - 1].zock_next = 0;

  return 0;
}


static inline unsigned
zock_id(unsigned z, bool tcp)
{
  zf_assume(z <= ZF_ZOCKET_ID_MAX);

  if( tcp )
    z += ZF_ZOCKET_ID_MAX + 1;

  zf_assume(z < zock_invalid);
  return z;
}


static inline unsigned
evict_node(struct queue* q)
{
  /* Drop the oldest report on the used list and re-use that node */
  unsigned node_id = q->nodes[0].used_next;
  zf_assert(node_id);
  struct node* node = &q->nodes[node_id];

  q->nodes[0].used_next = node->used_next;
  q->nodes[node->used_next].used_prev = 0;

  /* Inform the node's zocket that it has been dropped */
  zf_assert(node->zock != zock_invalid);
  struct zock* victim = &q->zocks[node->zock];
  victim->dropped = true;
  if( node_id == victim->head ) {
    victim->head = node->zock_next;
  }
  if( node_id == victim->tail ) {
    zf_assert(node->zock_next == 0);
    victim->tail = 0;
  }

  /* This means that the queue is to small to handle the maximum number of
   * in-flight packets. The size should be at least the total size of all tx
   * rings for this stack. */
  zf_assert(node_id != victim->pending);

  return node_id;
}


static inline unsigned
alloc_node(struct queue* q)
{
  unsigned node_id = q->nodes[0].zock_next;
  if( ZF_LIKELY(node_id) ) {
    /* There is a node on the free list, so remove and use it */
    q->nodes[0].zock_next = q->nodes[node_id].zock_next;
    zf_assert(q->nodes[node_id].zock == zock_invalid);
    return node_id;
  }

  return evict_node(q);
}


static inline void
free_node(struct queue* q, unsigned node_id)
{
  q->nodes[node_id].zock_next = q->nodes[0].zock_next;
  q->nodes[0].zock_next = node_id;
}


static inline void
add_node_to_zock(struct queue* q, unsigned node_id, unsigned zock_id)
{
  q->nodes[node_id].zock = zock_id;
  q->nodes[node_id].zock_next = 0;

  struct zock* zock = &q->zocks[zock_id];
  if( zock->tail )
    q->nodes[zock->tail].zock_next = node_id;
  zock->tail = node_id;
  if( ! zock->head )
    zock->head = node_id;
  if( ! zock->pending )
    zock->pending = node_id;
}


static inline void
remove_node_from_zock(struct queue* q, unsigned node_id)
{
  struct node* node = &q->nodes[node_id];

  unsigned zock_id = node->zock;
  zf_assert(zock_id != zock_invalid);
  node->zock = zock_invalid;

  struct zock* zock = &q->zocks[zock_id];
  zock->head = node->zock_next;
  if( zock->head == 0 )
    zock->tail = 0;
}


static inline void
add_node_to_used(struct queue* q, unsigned node_id)
{
  struct node* node = &q->nodes[node_id];

  node->used_next = 0;
  node->used_prev = q->nodes[0].used_prev;
  q->nodes[node->used_prev].used_next = node_id;
  q->nodes[0].used_prev = node_id;
}


static inline void
remove_node_from_used(struct queue* q, unsigned node_id)
{
  struct node* node = &q->nodes[node_id];

  q->nodes[node->used_next].used_prev = node->used_prev;
  q->nodes[node->used_prev].used_next = node->used_next;
}


static inline void
prepare(struct queue* q, unsigned z, bool tcp,
        unsigned start, unsigned bytes, unsigned flags)
{
  unsigned node_id = alloc_node(q);

  add_node_to_zock(q, node_id, zock_id(z, tcp));
  add_node_to_used(q, node_id);

  /* Write currently known information into the report.
   * The timestamp isn't available until completion. */
  struct zf_pkt_report* report = &q->nodes[node_id].report;
  report->start = start;
  report->bytes = bytes;
  report->flags = flags;
}


static inline void
complete(struct queue* q, unsigned z, bool tcp, ef_event* ev)
{
  zf_assert(EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP);

  struct zock* zock = &q->zocks[zock_id(z, tcp)];
  zf_assert(zock->pending);

  struct node* node = &q->nodes[zock->pending];
  zf_assert(node->zock == zock_id(z, tcp));
  zock->pending = node->zock_next;

  node->report.timestamp = {
    .tv_sec  = EF_EVENT_TX_WITH_TIMESTAMP_SEC(*ev),
    .tv_nsec = EF_EVENT_TX_WITH_TIMESTAMP_NSEC(*ev),
  };

  /* While ef_vi and TCPDirect have the same sync flags layout they can be
   * copied without translation. */
  static_assert(EF_VI_SYNC_FLAG_CLOCK_SET == ZF_PKT_REPORT_CLOCK_SET);
  static_assert(EF_VI_SYNC_FLAG_CLOCK_IN_SYNC == ZF_PKT_REPORT_IN_SYNC);
  node->report.flags |= EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(*ev);
}


static inline void
get(struct queue* q, unsigned z, bool tcp,
    struct zf_pkt_report* reports_out, int* count_in_out, bool* more_out)
{
  struct zock* zock = &q->zocks[zock_id(z, tcp)];

  int count = 0;
  while( zock->head != zock->pending && count < *count_in_out ) {
    unsigned node_id = zock->head;
    struct node* node = &q->nodes[node_id];

    reports_out[count] = node->report;
    if( zock->dropped ) {
      zock->dropped = false;
      reports_out[count].flags |= ZF_PKT_REPORT_DROPPED;
    }
    ++count;

    remove_node_from_used(q, node_id);
    remove_node_from_zock(q, node_id);
    free_node(q, node_id);
  }

  *count_in_out = count;
  *more_out = zock->head != zock->pending;
}

}
#endif

