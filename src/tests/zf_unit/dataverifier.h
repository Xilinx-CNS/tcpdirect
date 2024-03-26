/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2021 Advanced Micro Devices, Inc. */


/* This header declares and defines multiple singletons
 * do not pull it more than once into exectuable.
 * TODO sort this if worth the effort.
 */
extern "C" int already_included_or_linked;
int already_included_or_linked = 0;

#define O0 __attribute__((optimize("O0")))
#define debug_break() __asm__("int $3")

int __memsetx(uint8_t* buf, int magic, size_t len, int set)
{
  for( size_t i = 0; i < len; i++ ){
    size_t v = ((size_t)magic + i);
    /* just make it hex numbers so easy to figure out this is payload */
    v = (((v >> 2) >> ((v&3) * 4)) & 0xF );
    v += ( v < 10 ) ? '0' : 'A' - 10;
    if( set )
      buf[i] = v;
    else if( (uint8_t) buf[i] != (uint8_t) v )
      return 0x1000000 + i;
  }
  return 0;
}

void memsetx(void* buf, int magic, size_t len)
{
  __memsetx((uint8_t*)buf, magic, len, 1);
}

int memcmpx(const void* buf, int magic, size_t len)
{
  return __memsetx((uint8_t*)buf, magic, len, 0);
}


void quiesce_sender(zf_stack* stack, zft* tcp_tx)
{
  /* Wait untill all ACKs are received */
  while( tcp_has_sendq(&((zf_tcp*)tcp_tx)->pcb.sendq) )
    zf_reactor_perform(stack);
}

struct DataVerifier {
  zf_tcp* tcp_rx;
  zf_tcp* tcp_tx;
  uint32_t seq0;
  uint32_t magic0;
  uint32_t w;
  uint32_t r;

  bool enabledForRx(zf_tcp* _tcp_rx)
    { return tcp_rx == _tcp_rx; }

  bool enabledForTx(zf_tcp* _tcp_tx)
    { return tcp_tx == _tcp_tx; }

  void fillWBuf(char* data, int len)
  {
      memsetx(data, magic0 + w, len);
  }

  void O0 reportBadBuf(const char* data, uint32_t ofs, int len, int in_buf_ofs)
  {
    static char buf[1600];
    memsetx(buf, magic0 + ofs, len);
    int cmp = memcmp(data, buf, len);
    diag("Data mismach data %p len %d in-buf-ofs %d relseqno %d cmp %02x vs %02x (%d)",
         data, len, in_buf_ofs, ofs + in_buf_ofs, buf[in_buf_ofs], data[in_buf_ofs], cmp);
    debug_break();
  }
  bool __verifyBuf(const char* data, uint32_t ofs, int len)
  {
    int in_buf_ofs;
    if( ofs + len > w ) {
      return false;
    }
    if( (in_buf_ofs = memcmpx(data, magic0 + ofs, len)) == 0 )
      return true;
    // Let's show what went wrong
    in_buf_ofs -= 0x1000000;
    reportBadBuf(data, ofs, len, in_buf_ofs);
    return false;
  }

  bool verifyBuf(const char* data, uint32_t seqno, int len)
  {
    if( len == 0 )
      return true;
    if( (int32_t)(seqno - seq0) < 0 )
      return false;
    return __verifyBuf(data, seqno - seq0, len);
  }

  bool verifyRBuf(const char* data, int len, int extra_ofs = 0)
  {
    return __verifyBuf(data, r + extra_ofs, len);
  }

  void accountWritten(int len)
    { w += len; }
  void accountRead(int len)
    { r += len; }


  struct Guard {
    DataVerifier& v;
    Guard(DataVerifier& _v, int _magic, struct zft* tcp_tx, struct zft* tcp_rx) : v(_v)
    {
      zf_tcp* tcp = (struct zf_tcp*)tcp_tx;
      auto pcb = &tcp->pcb;
      quiesce_sender(zf_stack_from_zocket(tcp_tx), tcp_tx);
      v.tcp_tx = (struct zf_tcp*)tcp_tx;
      v.tcp_rx = (struct zf_tcp*)tcp_rx;
      v.seq0 = pcb->snd_lbb;
      v.magic0 = _magic;
      v.w = 0;
      v.r = 0;
    }
    ~Guard()
    {
      v.tcp_tx = 0;
    }
  };


} verifier;


struct SegmentDropper {
  zf_tcp* tcp_rx;
  int32_t loss_pct;
  int32_t loss_len;

  SegmentDropper() : loss_len(-1) {}

  bool shouldDropPkt(zf_tcp* _tcp_rx, int payload_len)
  {
    if( _tcp_rx != tcp_rx )
        return false;
    if( payload_len == 0 )
      return false;
    if( loss_len >= 0 && payload_len != loss_len )
      return false;
    return loss_pct > 0 && (random() % 100) <= loss_pct;
  }

  struct Guard {
    SegmentDropper& d;
    Guard(SegmentDropper& _d, zf_tcp* tcp_rx, int pct, int len = -1) : d(_d)
    {
      d.loss_pct = pct;
      d.loss_len = len;
      d.tcp_rx = tcp_rx;
    }
    ~Guard()
    {
      d.loss_pct = 0;
    }
  };

} dropper;

static inline bool
verify_data(const char* data, int length, bool account = true, int extra_ofs = 0)
{
  if( account == true )
    extra_ofs = 0;
  bool r = verifier.verifyRBuf(data, length, extra_ofs);
  if( account )
    verifier.accountRead(length);
  return r;
}

static inline bool
verify_iov(struct iovec *iov,
           ssize_t length = -1, bool account = true, int extra_ofs = 0)
{
  if( length == -1 )
    length = iov->iov_len;
  return verify_data((const char*)iov->iov_base, length, account, extra_ofs);
}

template <typename MSG>
int verify_msg(MSG& msg, bool account = true)
{
  bool passed = true;
  int recved = 0;
  /* currently checking - no zero-length iovecs */
  for( int i = 0; i < msg.header.iovcnt; i++ ) {
    int len = msg.iov[i].iov_len;
    if( len <= 0 || len > 2000 ) {
      diag("invalid iov[%d] len %d", i, len);
      debug_break();
      return -1;
    }
    passed &=
      verify_iov(&msg.iov[i], -1, account, account ? 0 : recved);
    recved += len;
  }
  return passed ? recved : -1;
}



static inline bool O0
verify_txq(struct zft* tcp_tx)
{
  zf_tcp* tcp = (struct zf_tcp*)tcp_tx;

  if( ! verifier.enabledForTx(tcp) )
    return true;

  auto pcb = &tcp->pcb;
  auto sendq = &pcb->sendq;
  if( ! tcp_has_sendq(sendq) )
    return true;

  int ok = true;
  auto lbb = pcb->snd_lbb;
  for( auto i = sendq->end; i != sendq->begin; i-- ) {
    auto seg = tcp_seg_at(sendq, i - 1);
    auto seqno = tcp_seg_seq(seg);
    auto len = tcp_seg_len(seg);
    ZF_TEST(seqno + len == lbb);
    auto payload = (char*)(tcp_seg_tcphdr(seg) + 1);
    lbb -= len;
    ok &= verifier.verifyBuf(payload, lbb, len);
  }
  return ok;
}

extern "C"
int tcp_frame_hook(zf_tcp* tcp_rx, const char* payload, uint32_t len, uint32_t seqno)
{
  /* root of tcp rx path calls as here with a segment
   * verify each segment, retransmitted or not contains correct data.
   */
  if( verifier.enabledForRx(tcp_rx) ) {
    // for now let us just crash the test app in case of corruption
    // diag("Verifying %u:%u(%d)\n", seqno, seqno + len, len);
    ZF_TEST(verifier.verifyBuf(payload, seqno, len));
  }
  // diag("frame verified");

  int dropPkt = dropper.shouldDropPkt(tcp_rx, len);
  if( dropPkt )
    ; // diag("Dropped %u:%u(%d)\n", seqno, seqno + len, len);
  return !dropPkt;
}
