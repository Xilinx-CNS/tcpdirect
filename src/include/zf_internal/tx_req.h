/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_TX_REQ_H__
#define __ZF_INTERNAL_TX_REQ_H__


/* This zf_tx_req_id must match with ef_request_id, but we use a separate
 * type to define internal structure and flags. */
typedef uint32_t zf_tx_req_id;
/* See MAX_PKT_NIC_PAGES: 32K packet buffer ids fit into 15 bits,
 * and another bit is invalid marker: */
static const zf_tx_req_id ZF_REQ_ID_PKT_ID_MASK   = 0x0000ffff;
/* Mask to get UDP or TCP zocket ID */
static const zf_tx_req_id ZF_REQ_ID_ZOCK_ID_MASK  = 0x003f0000;
static const int ZF_REQ_ID_ZOCK_ID_SHIFT = 16;
/* Aux data: currently, it is index in the TCP send queue: */
static const zf_tx_req_id ZF_REQ_ID_AUX_MASK      = 0x0fc00000;
static const int ZF_REQ_ID_AUX_SHIFT = 22;
/* For UDP, aux data has a flag to indicate fragmentation, set on all
 * fragments except the last.
 * ZF_REQ_ID_UDP_FRAGMENT uses the same bit as ZF_REQ_ID_AUX_MASK.
 * It's OK because ZF_REQ_ID_AUX_MASK is only used for TCP now. */
static const zf_tx_req_id ZF_REQ_ID_UDP_FRAGMENT  = 0x00800000;
/* Protocol field: UDP or three flavours of TCP packet
 *   Segment data, which might be retained by the zocket
 *   empty ACK or similar, to be freed on completion
 *   alternative, not to be freed */
static const zf_tx_req_id ZF_REQ_ID_PROTO_MASK     = 0x30000000;
static const zf_tx_req_id ZF_REQ_ID_PROTO_UDP      = 0x00000000;
static const zf_tx_req_id ZF_REQ_ID_PROTO_TCP_KEEP = 0x10000000;
static const zf_tx_req_id ZF_REQ_ID_PROTO_TCP_FREE = 0x20000000;
static const zf_tx_req_id ZF_REQ_ID_PROTO_TCP_ALT  = 0x30000000;
/* Other control flags */
static const zf_tx_req_id ZF_REQ_ID_PIO_FLAG      = 0x40000000;
static const zf_tx_req_id ZF_REQ_ID_CTPIO_FLAG    = 0x80000000;
static const zf_tx_req_id ZF_REQ_ID_CONTROL_MASK  = 0xf0000000;
static const zf_tx_req_id ZF_REQ_ID_INVALID       = -1;


#endif
