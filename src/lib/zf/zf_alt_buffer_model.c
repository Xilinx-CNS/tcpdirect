/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_alts.h>
#include <zf_internal/attr.h>

#include <etherfabric/ef_vi.h>


#define MEDFORD_BYTES_PER_WORD    (32)
#define MEDFORD_ADD_BUFFER_THRESHOLD (7)

static inline int zf_altbm_medford_init(struct zf_alt_buffer_model* bm,
                                        struct zf_stack_res_nic* sti_nic,
                                        struct zf_attr* attr)
{
  unsigned long cap_buffer_size;
  int rc = ef_pd_capabilities_get(sti_nic->dh,
                                  &sti_nic->pd, sti_nic->dh,
                                  EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFER_SIZE,
                                  &cap_buffer_size);
  if( rc != 0 ) {
    zf_log_stack_err(zf_stack_from_zocket(bm),
                     "%s: ERROR: failed to query buffer size: rc=%d", __func__,
                     rc);
    return rc;
  }

  bm->medford.buffer_size = cap_buffer_size;
  bm->medford.total_buffers = attr->alt_buf_size / bm->medford.buffer_size;
  bm->medford.words_per_buffer = bm->medford.buffer_size /
                                 MEDFORD_BYTES_PER_WORD;

  /* The ef_vi layer adds 2 switch buffers per alt. */
  bm->medford.total_buffers += 2 * attr->alt_count;

  bm->medford.n_alts = attr->alt_count;

  return 0;
}


/* Return the total number of vswitch buffers allocated to the VFIFO
 * corresponding to this alt. */
static inline unsigned 
zf_altbm_medford_buffers_used(struct zf_alt_buffer_model* bm,
                              int althandle)
{
  uint16_t head_buf = bm->medford.alt[althandle].head_ptr /
                      bm->medford.words_per_buffer;
  uint16_t tail_buf = bm->medford.alt[althandle].tail_ptr /
                      bm->medford.words_per_buffer;

  unsigned n_bufs = ((uint16_t)(head_buf - tail_buf)) + 1;

  /* New buffers are allocated at the head end a few clocks before
   * they are needed. Account for that here. */

  uint16_t head_ofs = bm->medford.alt[althandle].head_ptr
                      - (head_buf * bm->medford.words_per_buffer);

  if( head_ofs > bm->medford.words_per_buffer - MEDFORD_ADD_BUFFER_THRESHOLD )
    n_bufs += 1;

  return n_bufs;
}


/* Return the number of streaming words which are available to hold
 * data for this alt (assuming it can use all the free buffers if it
 * wishes). */
static inline unsigned 
zf_altbm_medford_words_free(struct zf_alt_buffer_model* bm,
                            int althandle)
{
  /* Work out how many buffers are assigned to alternatives. */

  int free_buffers = bm->medford.total_buffers;
  for( unsigned i = 0; i < bm->medford.n_alts; i++ ) {
    free_buffers -= zf_altbm_medford_buffers_used( bm, i );
  }

  if( free_buffers < 0 )
    return 0;

  /* All non-assigned buffers are available to store fresh data. */

  uint32_t free_words = free_buffers * bm->medford.words_per_buffer;

  /* There is probably also some space available in the last buffer
   * assigned to the current alt. */

  uint32_t head_ptr = bm->medford.alt[althandle].head_ptr;
  uint32_t head_buf = head_ptr / bm->medford.words_per_buffer;
  uint32_t head_ofs = head_ptr - (head_buf * bm->medford.words_per_buffer);

  free_words += bm->medford.words_per_buffer - head_ofs;

  /* New buffers are allocated at the head end a few clocks before
   * they are needed. Account for that here. */

  if( head_ofs > bm->medford.words_per_buffer - MEDFORD_ADD_BUFFER_THRESHOLD )
    free_words += bm->medford.words_per_buffer;

  return free_words;
}


/* Return the number of streaming bus words occupied by a packet with
 * the given size in bytes. */
static inline unsigned zf_altbm_medford_packet_words(unsigned size_bytes)
{
  unsigned pkt_len_words = (size_bytes + MEDFORD_BYTES_PER_WORD - 1)
                           / MEDFORD_BYTES_PER_WORD;
  pkt_len_words++; /* add one for filter-info word */
  return pkt_len_words;
}


size_t zf_altbm_medford_bytes_free(struct zf_alt_buffer_model* bm,
                                   int althandle)
{
  uint32_t free_words = zf_altbm_medford_words_free(bm, althandle);

  if( free_words > 0 )
    free_words -= 1;

  return MEDFORD_BYTES_PER_WORD * free_words;
}


int zf_altbm_medford_send_packet(struct zf_alt_buffer_model* bm,
                                 int althandle,
                                 unsigned pkt_size_bytes)
{
  unsigned pkt_len_words = zf_altbm_medford_packet_words(pkt_size_bytes);

  if( zf_altbm_medford_words_free(bm, althandle) < pkt_len_words )
    return 0;

  bm->medford.alt[althandle].head_ptr += pkt_len_words;

  return 1;
}


void zf_altbm_medford_unsend_packet(struct zf_alt_buffer_model* bm,
                                    int althandle,
                                    unsigned pkt_size_bytes)
{
  unsigned pkt_len_words = zf_altbm_medford_packet_words(pkt_size_bytes);
  bm->medford.alt[althandle].head_ptr -= pkt_len_words;
}


static inline void zf_altbm_medford_alt_reset(struct zf_alt_buffer_model* bm,
                                              int althandle)
{
  bm->medford.alt[althandle].tail_ptr = bm->medford.alt[althandle].head_ptr;
}


/* Now the hardware-independent equivalents to the above. */


unsigned zf_altbm_bytes_free(struct zf_alt_buffer_model* bm,
                             int althandle)
{
  switch( bm->nic_type->arch ) {

  case EF_VI_ARCH_EF10:
    return zf_altbm_medford_bytes_free(bm, althandle);

  default:
    zf_assert( 0 );
    return 0;
  }
}


int zf_altbm_send_packet(struct zf_alt_buffer_model* bm,
                         int althandle,
                         unsigned pkt_size_bytes)
{
  switch( bm->nic_type->arch ) {

  case EF_VI_ARCH_EF10:
    return zf_altbm_medford_send_packet(bm, althandle,
                                        pkt_size_bytes);

  default:
    zf_assert( 0 );
    return 0;
  }
}


void zf_altbm_unsend_packet(struct zf_alt_buffer_model* bm,
                            int althandle,
                            unsigned pkt_size_bytes)
{
  switch( bm->nic_type->arch ) {

  case EF_VI_ARCH_EF10:
    zf_altbm_medford_unsend_packet(bm, althandle,
                                   pkt_size_bytes);
    break;

  default:
    zf_assert( 0 );
    break;
  }
}


void zf_altbm_alt_reset(struct zf_alt_buffer_model* bm,
                        int althandle)
{
  switch( bm->nic_type->arch ) {

  case EF_VI_ARCH_EF10:
    zf_altbm_medford_alt_reset(bm, althandle);
    break;

  default:
    zf_assert( 0 );
    break;
  }
}


int zf_altbm_init(zf_alt_buffer_model* bm,
		  zf_stack_impl* sti, int nic_no,
                  struct zf_attr* attr)
{
  struct zf_stack_res_nic* sti_nic = &sti->nic[nic_no];

  memset(bm, 0, sizeof(*bm));
  bm->nic_type = &zf_stack_nic_tx_vi(&sti->st, 0)->nic_type;

  switch( bm->nic_type->arch ) {

  case EF_VI_ARCH_EF10:

    /* Huntington, Medford or Medford 2.  Huntington doesn't support
     * alternatives, and the "medford" model is valid for Medford 2 as well. */

    return zf_altbm_medford_init(bm, sti_nic, attr);

  default:

    /* Unknown NIC type. */

    zf_assert( 0 );
    return -EINVAL;
  }

}
