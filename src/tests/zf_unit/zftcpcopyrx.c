/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc. */
#include <zf/zf.h>

#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>

#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/zf_stack.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"

#include "dataverifier.h"


struct {
  struct zf_stack* stack;
  struct zf_attr* attr;

  struct abstract_zocket_pair zockets;
  struct zft* tx;
  struct zft* rx;
} ctx;


#define ZF_TRY_RETURN(x)                                                \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: ZF_TRY(%s) failed\n", __func__, #x);  \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d (%s) errno=%d (%s)\n",              \
              __rc, strerror(-__rc), errno, strerror(errno));           \
      return __rc;                                                      \
    }                                                                   \
  } while( 0 )

static const char *cur_test;


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  ZF_TRY_RETURN(zf_init());

  ZF_TRY_RETURN(zf_attr_alloc(attr_out));

  int rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  return 0;
}


static int fini(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  zf_deinit();

  return 0;
}


static int init_sockets(void)
{
  alloc_tcp_pair(ctx.stack, ctx.attr, &ctx.zockets);
  ctx.tx = (struct zft*)ctx.zockets.opaque_tx;
  ctx.rx = (struct zft*)ctx.zockets.opaque_rx;

  return 0;
}


static int fini_sockets(void)
{
  while( zft_shutdown_tx(ctx.tx) == -EAGAIN )
    zf_reactor_perform(ctx.stack);

  while( zft_shutdown_tx(ctx.rx) == -EAGAIN )
    zf_reactor_perform(ctx.stack);

  while( zft_state(ctx.tx) != TCP_CLOSE )
    zf_reactor_perform(ctx.stack);

  while( zft_state(ctx.rx) != TCP_CLOSE )
    zf_reactor_perform(ctx.stack);

  ZF_TRY_RETURN(zft_free(ctx.tx));
  ZF_TRY_RETURN(zft_free(ctx.rx));

  ctx.tx = NULL;
  ctx.rx = NULL;

  return 0;
}


#define MAX_SEND_BYTES 1024

static int send_bytes(size_t n)
{
  char bytes[MAX_SEND_BYTES];
  struct iovec iov;

  cmp_ok(n, "<", MAX_SEND_BYTES, 
         "%s: Send length is acceptable", cur_test);

  verifier.fillWBuf(bytes,n);

  iov.iov_base = bytes;
  iov.iov_len = n;

  ZF_TRY_RETURN(zft_send(ctx.tx, &iov, 1, 0));
  verifier.accountWritten(n);
  while(zf_reactor_perform(ctx.stack) == 0);
  while(zf_reactor_perform(ctx.stack) != 0);
  return 0;
}




/* Simplest possible test: send some data and receive it exactly. */
static int test_simple(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer[100];
  struct iovec iov = { buffer, sizeof(buffer) };
  int iovcnt = 1;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count correct", cur_test);
  ok(verify_iov(&iov, 100), "%s: pass", cur_test);

  return 0;
}


/* zero len iov in receive buffer should not terminate read early */
static int test_zerolen_iov(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer[100];
  struct iovec iov_verify = { buffer, sizeof(buffer) };
  struct iovec iov[5] = {
      0,0,
      buffer, 50,
      0,0,
      buffer + 50, sizeof(buffer) - 50,
      0,0,
      };
  int iovcnt = 5;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count correct", cur_test);
  ok(verify_iov(&iov_verify, 100), "%s: pass", cur_test);

  return 0;
}


/* Send some data and then read it in two separate zft_recv calls. */
static int test_read_twice(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer[50];
  struct iovec iov = { buffer, sizeof(buffer) };
  int iovcnt = 1;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0));

  cmp_ok(bytes, "==", 50,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov, 50), "%s: read1 data ok", cur_test);

  iov = { buffer, sizeof(buffer) };
  iovcnt = 1;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0));

  cmp_ok(iovcnt, "==", 1,
         "%s: bytes read count is correct", cur_test);
  cmp_ok(bytes, "==", 50,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov, 50), "%s: read2 data ok", cur_test);

  return 0;
}


/* Send some data and then read it into two iovecs. */
static int test_read_two_iovs(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer1[50], buffer2[50];
  struct iovec iov[] = {
    { buffer1, sizeof(buffer1) },
    { buffer2, sizeof(buffer2) }
  };
  int iovcnt = 2;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov[0], 50), "%s: iov1 data ok", cur_test);
  ok(verify_iov(&iov[1], 50), "%s: iov2 data ok", cur_test);

  return 0;
}


/* Test a zft_recv() that only partially fills its iov. */
static int test_read_partial(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer[150];
  struct iovec iov = { buffer, sizeof(buffer) };
  int iovcnt = 1;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov, 100), "%s: pass", cur_test);

  return 0;
}


/* Test a zft_recv() that doesn't use all of its iovs. */
static int test_read_only_one(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer1[150], buffer2[150];
  struct iovec iov[] = {
    { buffer1, sizeof(buffer1) },
    { buffer2, sizeof(buffer2) }
  };
  int iovcnt = 2;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov[0], 100), "%s: pass", cur_test);

  return 0;
}


/* Fill one iov completely, then partially fill the next. */
static int test_read_1andabit(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  char buffer1[70], buffer2[70];
  struct iovec iov[] = {
    { buffer1, sizeof(buffer1) },
    { buffer2, sizeof(buffer2) }
  };
  int iovcnt = 2;
  int bytes = 0;

  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov[0], 70), "%s: iov1 data ok", cur_test);
  ok(verify_iov(&iov[1], 30), "%s: iov2 data ok", cur_test);

  return 0;
}


/* Test that zft_recv() handles EOF correctly. */
static int test_eof(void)
{
  ZF_TRY_RETURN(send_bytes(100));

  while( zft_shutdown_tx(ctx.tx) == -EAGAIN )
    zf_reactor_perform(ctx.stack);

  while( zft_state(ctx.tx) != TCP_FIN_WAIT2 )
    zf_reactor_perform(ctx.stack);

  char buffer[150];
  struct iovec iov = { buffer, sizeof(buffer) };
  int iovcnt = 1;
  int bytes = 0;

  /* The zocket now contains some data plus an EOF marker. */
  ZF_TRY_RETURN(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0));

  cmp_ok(bytes, "==", 100,
         "%s: bytes read count is correct", cur_test);
  ok(verify_iov(&iov, 100), "%s: data ok", cur_test);

  /* We've consumed the data, but the EOF marker should still be there.
   * Subsequent zft_recv() calls should succeed (and in particular should not
   * fail with -EAGAIN), but should report zero bytes/buffers populated.  Try
   * this twice to make sure we don't break things the first time. */

  iovcnt = 1;
  cmp_ok(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0), "==", 0,
         "%s: zft_recv() with EOF and no data succeeded", cur_test);
  cmp_ok(bytes, "==", 0, "%s: bytes read count is correct", cur_test);

  iovcnt = 1;
  cmp_ok(bytes = zft_recv(ctx.rx, &iov, iovcnt, 0), "==", 0,
         "%s: zft_recv() with EOF and no data succeeded again", cur_test);
  cmp_ok(bytes, "==", 0, "%s: bytes read count is correct", cur_test);

  return 0;
}


/* Stress test: send random lengths, receive into a random number of
 * random-length IOVs. */

#define STRESS_TEST_LENGTH 10000000
#define STRESS_MTU 1500
#define STRESS_MAX_RX_BUFS 10
#define STRESS_MAX_RX_CHUNK 1000

static int __test_stress(size_t max_bytes_in_flight)
{
  unsigned bytes_in_flight = 0;
  unsigned bytes_received = 0;
  unsigned bytes_sent = 0;
  char send_buffer[STRESS_MTU];
  char receive_buffers[STRESS_MAX_RX_BUFS][STRESS_MAX_RX_CHUNK];
  bool passed = true;

  int seed = zf_frc64();
  srandom(seed);
  diag("%s: Using seed %d", cur_test, seed);

  while( bytes_received < STRESS_TEST_LENGTH ) {

    while( bytes_in_flight < max_bytes_in_flight  && bytes_sent < STRESS_TEST_LENGTH ) {
      size_t to_send = 1 + (rand() % (STRESS_MTU - 1));
      size_t available;

      ZF_TRY(zft_send_space(ctx.tx, &available));

      if( available < to_send )
        to_send = available;

      if( to_send > 0 ) {
        verifier.fillWBuf(send_buffer, to_send);
        struct iovec iov = { send_buffer, to_send };
        ssize_t sent;
        ZF_TRY(sent = zft_send(ctx.tx, &iov, 1, 0));
        /* We clamped [to_send] to [available], so we don't expect partial
         * sends. */
        ZF_TEST((size_t) sent == to_send);

        verifier.accountWritten(sent);

        bytes_in_flight += to_send;
        bytes_sent += to_send;
      }

      zf_reactor_perform(ctx.stack);
    }

    zf_reactor_perform(ctx.stack);

    if( rand() % 5 == 0 ) {
      struct {
        struct zft_msg zcr;
        struct iovec iov[2];
      } msg;
      msg.zcr.iovcnt = 2;

      zft_zc_recv(ctx.rx, &msg.zcr, 0);

      if( msg.zcr.iovcnt > 0)  {
        for( int i = 0; i < msg.zcr.iovcnt; i++ ) {
          passed &=
            verify_iov(&msg.iov[i]);
          bytes_received += msg.iov[i].iov_len;
          bytes_in_flight -= msg.iov[i].iov_len;
        }

        ZF_TRY_RETURN(zft_zc_recv_done(ctx.rx, &msg.zcr));
      }

    } else {
      struct iovec rx_iov[STRESS_MAX_RX_BUFS];
      int rx_bufs = 1 + (rand() % (STRESS_MAX_RX_BUFS - 1));
      int bytes = 0, max = 0;

      for( int i = 0; i < rx_bufs; i++ ) {
        rx_iov[i].iov_base = receive_buffers[i];
        rx_iov[i].iov_len = 1 + (rand() % (STRESS_MAX_RX_CHUNK - 1));
        max += rx_iov[i].iov_len;
      }

      bytes = zft_recv(ctx.rx, rx_iov, rx_bufs, 0);
      if( bytes == -EAGAIN )
        continue;
      ZF_TRY_RETURN(bytes);

      if( bytes <= 0 || bytes > max ) {
        diag("%s: byte range!", cur_test);
        passed = false;
      }

      for( int i = 0; i < rx_bufs; i++ ) {
        unsigned bytes_to_check = MIN(rx_iov[i].iov_len, (unsigned)bytes);
        bytes -= bytes_to_check;
        passed &=
          verify_data(&receive_buffers[i][0], bytes_to_check);
        bytes_in_flight -= bytes_to_check;
        bytes_received += bytes_to_check;
        if( bytes == 0 )
          break;
      }
      if( bytes != 0 ) {
        diag("%s: byte count mismatch!", cur_test);
        passed = false;
      }
    }
  }

  ok(passed, "%s: stress test passed", cur_test);

  return 0;
}

static int test_stress()
{
  return __test_stress(30000);
}

static int test_stress_overfill()
{
  return __test_stress(90000);
}

#define TEST(a) { #a , a }

static struct {
  const char *name;
  int (*test)(void);
} tests[] = {
  TEST(test_simple),
  TEST(test_read_twice),
  TEST(test_read_two_iovs),
  TEST(test_read_partial),
  TEST(test_read_only_one),
  TEST(test_read_1andabit),
  TEST(test_eof),
  TEST(test_zerolen_iov),
  TEST(test_stress),
  TEST(test_stress_overfill),
};


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  memset(&ctx, 0, sizeof(ctx));

  ctx.stack = stack;
  ctx.attr = attr;

  plan(35);

  for( unsigned i = 0; i < sizeof(tests)/sizeof(tests[0]); i++ ) {
    cur_test = tests[i].name;
    ZF_TRY_RETURN(init_sockets());
    {
      DataVerifier::Guard vg(verifier, 5, ctx.tx, ctx.rx);
      tests[i].test();
    }
    ZF_TRY_RETURN(fini_sockets());
  }

  return 0;
}


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY_RETURN(init(&stack, &attr));
  rc = test(stack, attr);
  ZF_TRY_RETURN(fini(stack, attr));

  return rc;
}

