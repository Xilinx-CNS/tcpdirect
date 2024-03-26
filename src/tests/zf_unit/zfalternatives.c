/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2020 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/tcp.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/private/zf_emu.h>

#include <ci/efhw/mc_driver_pcol.h>

#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <math.h>

#include "../tap/tap.h"


#define NA 8 /* Number of alternatives to use */

#define DATA_TIMEOUT 50000 /* Microseconds to wait for data to arrive */
#define MAX_PKT_SIZE 1024
#define MAX_CWND 32767

struct recvs {
  struct zft* zocket;
  int iov_ptr;
  struct zft_msg zcr;
  struct iovec iov[5];
};


struct {
  struct zf_stack* stack;
  struct zf_attr* attr;

  /* Listening socket */
  struct sockaddr_in listen_addr;
  struct zftl* listener;
  recvs l;

  /* Connecting socket */
  struct sockaddr_in bind_addr;
  struct zft_handle* tcp_c;
  recvs c;
  zf_althandle alts[NA];
  int n_alts;
} ctx;


#define STRING(s) { (void*)s, sizeof(s) }

struct iovec iovs[] = {
  STRING("Hello World\n"),
  STRING("Bonjour le monde\n"),
  STRING("Hej Verden\n"),
  STRING("This is a much longer string which is used by tests which"
         "require a much larger amount of data, such as the test"
         "which deliberately closes the receiver's window in order"
         "to verify that the behaviour is correct when trying to send"
         "an alternative which would overflow the available space."),
  STRING("This is an even longer string which is used by tests which"
         "require a much larger amount of data, such as the test"
         "which queues data that requires segmentation."
         "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25"
         "26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 "
         "48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 7"
         "0 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92"
         "93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 1"
         "11 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 "
         "128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144"
         "145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 16"
         "1 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 1"
         "78 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 "
         "195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211"
         "212 213 214 215 216 217 218 219 220 221 222 223 224 225 226 227 22"
         "8 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 2"
         "45 246 247 248 249 250 251 252 253 254 255 256 257 258 259 260 261 "
         "262 263 264 265 266 267 268 269 270 271 272 273 274 275 276 277 278"
         "279 280 281 282 283 284 285 286 287 288 289 290 291 292 293 294 29"
         "5 296 297 298 299 300 301 302 303 304 305 306 307 308 309 310 311 3"
         "12 313 314 315 316 317 318 319 320 321 322 323 324 325 326 327 328 "
         "329 330 331 332 333 334 335 336 337 338 339 340 341 342 343 344 345"
         "346 347 348 349 350 351 352 353 354 355 356 357 358 359 360 361 36"
         "2 363 364 365 366 367 368 369 370 371 372 373 374 375 376 377 378 3"
         "79 380 381 382 383 384 385 386 387 388 389 390 391 392 393 394 395 "
         "396 397 398 399 400 401 402 403 404 405 406 407 408 409 410 411 412"
         "413 414 415 416 417 418 419 420 421 422 423 424 425 426 427 428 42"
         "9 430 431 432 433 434 435 436 437 438 439 440 441 442 443 444 445 4"
         "46 447 448 449 450 451 452 453 454 455 456 457 458 459 460 461 462 "
         "463 464 465 466 467 468 469 470 471 472 473 474 475 476 477 478 479"
         "480 481 482 483 484 485 486 487 488 489 490 491 492 493 494 495 49"
         "6 497 498 499 500 501 502 503 504 505 506 507 508 509 510 511 512 5"
         "13 514 515 516 517 518 519 520 521 522 523 524 525 526 527 528 529 "
         "530 531 532 533 534 535 536 537 538 539 540 541 542 543 544 545 546"
         "547 548 549 550 551 552 553 554 555 556 557 558 559 560 561 562 56"
         "3 564 565 566 567 568 569 570 571 572 573 574 575 576 577 578 579 5"
         "80 581 582 583 584 585 586 587 588 589 590 591 592 593 594 595 596 "
         "597 598 599 600 601 602 603 604 605 606 607 608 609 610 611 612 613"
         "614 615 616 617 618 619 620 621 622 623 624 625 626 627 628 629 63"
         "0 631 632 633 634 635 636 637 638 639 640 641 642 643 644 645 646 6"
         "47 648 649 650 651 652 653 654 655 656 657 658 659 660 661 662 663 "
         "664 665 666 667 668 669 670 671 672 673 674 675 676 677 678 679 680"
         "681 682 683 684 685 686 687 688 689 690 691 692 693 694 695 696 69"
         "7 698 699 700 701 702 703 704 705 706 707 708 709 710 711 712 713 7"
         "14 715 716 717 718 719 720 721 722 723 724 725 726 727 728 729 730 "
         "731 732 733 734 735 736 737 738 739 740 741 742 743 744 745 746 747"
         "748 749 750 751 752 753 754 755 756 757 758 759 760 761 762 763 76"
         "4 765 766 767 768 769 770 771 772 773 774 775 776 777"),
};


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


static int init_stack(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  ZF_TRY_RETURN(zf_attr_alloc(attr_out));

  int rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  return 0;
}


static int fini_stack(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  return 0;
}


static void zsleep(struct zf_stack* stack, unsigned micros)
{
  struct timeval start, cur;
  unsigned waited;

  gettimeofday(&start, NULL);
  for(;;) {
    zf_reactor_perform(stack);

    gettimeofday(&cur, NULL);

    waited = (((cur.tv_sec - start.tv_sec) * 1000000) + 
              (cur.tv_usec - start.tv_usec));
    if( waited >= micros )
      return;
  }
}


static int init_sockets(void)
{
  ZF_TRY_RETURN(zft_alloc(ctx.stack, ctx.attr, &ctx.tcp_c));

  ZF_TRY_RETURN(zft_addr_bind(ctx.tcp_c, (struct sockaddr*)&ctx.bind_addr,
                              sizeof(ctx.bind_addr), 0));

  ctx.listen_addr = ctx.bind_addr;
  ctx.listen_addr.sin_port = htons(0);

  ZF_TRY_RETURN(zftl_listen(ctx.stack, (struct sockaddr*)&ctx.listen_addr,
                            sizeof(ctx.listen_addr), ctx.attr,
                            &ctx.listener));
  struct sockaddr_in la;
  socklen_t lla = sizeof(la);
  zftl_getname(ctx.listener, (struct sockaddr*)&la, &lla);
  ctx.listen_addr.sin_port = la.sin_port;

  ZF_TRY_RETURN(zft_connect(ctx.tcp_c, (struct sockaddr*)&ctx.listen_addr,
                            sizeof(ctx.listen_addr), &ctx.c.zocket));

  while( zftl_accept(ctx.listener, &ctx.l.zocket) == -EAGAIN )
    zf_reactor_perform(ctx.stack);

  int rc = 0;
  for( int i = 0; (i < NA) && (rc == 0); ++i ) {
    rc = zf_alternatives_alloc(ctx.stack, ctx.attr, &ctx.alts[i]);
  }
  cmp_ok(rc, "==", 0,
         "%s: Allocated sufficient alternatives", cur_test);

  return 0;
}


static int fini_sockets(void)
{
  for( int i = 0; i < NA; ++i ) {
    zf_alternatives_release(ctx.stack, ctx.alts[i]);
  }

  while( zft_shutdown_tx(ctx.c.zocket) == -EAGAIN )
    zf_reactor_perform(ctx.stack);

  while( zft_shutdown_tx(ctx.l.zocket) == -EAGAIN )
    zf_reactor_perform(ctx.stack);

  while( zft_state(ctx.c.zocket) != TCP_CLOSE )
    zf_reactor_perform(ctx.stack);

  while( zft_state(ctx.l.zocket) != TCP_CLOSE )
    zf_reactor_perform(ctx.stack);

  ZF_TRY_RETURN(zft_free(ctx.c.zocket));
  ZF_TRY_RETURN(zft_free(ctx.l.zocket));
  ZF_TRY_RETURN(zftl_free(ctx.listener));

  ctx.c.zocket = NULL;
  ctx.l.zocket = NULL;

  return 0;
}


/* Poll until either there is data waiting to be read or 1ms has
 * elapsed. Return true if there is data or false if the timer
 * expired. */
static int poll_for_data(recvs *rxc)
{
  struct timeval start, cur;
  unsigned waited;

  gettimeofday(&start, NULL);
  for(;;) {
    if( rxc->iov_ptr < rxc->zcr.iovcnt )
      return 1;

    zf_reactor_perform(ctx.stack);

    gettimeofday(&cur, NULL);

    waited = (((cur.tv_sec - start.tv_sec) * 1000000) +
              (cur.tv_usec - start.tv_usec));
    if(waited >= DATA_TIMEOUT)
      return 0;

    rxc->zcr.iovcnt = 5;
    zft_zc_recv(rxc->zocket, &rxc->zcr, 0);
    if( rxc->zcr.iovcnt > 0 )
      rxc->iov_ptr = 0;
  }
}


/* Verify that there is no data waiting to be read. Wait for up to
 * 1ms, in case there is in-flight data that hasn't arrived. */
static int verify_no_data(recvs *rxc)
{
  if( poll_for_data(rxc) )
    fail("%s: Data received when not expected", cur_test);

  return 0;
}


/* Verify that there is data waiting to be read. Compare it to the
 * supplied IOV and fail if it doesn't match. Wait for up to 1ms, in
 * case there is in-flight data that hasn't arrived. */
static int verify_data(recvs *rxc, struct iovec *data)
{
  if( !poll_for_data(rxc) )
    fail("%s: Timeout waiting for data", cur_test);

  /* Right now, reading from the socket will only ever return entire
   * packets, one per IOV. If that ever changes then this code will
   * need to be revisited. */

  cmp_ok(rxc->zcr.iovcnt, ">", 0,
         "%s: Data received", cur_test);
  if( rxc->zcr.iovcnt == 0 )
    return -1;

  struct iovec *rx = &rxc->iov[rxc->iov_ptr];

  cmp_ok(rx->iov_len, "==", data->iov_len,
         "%s: Received length matches", cur_test);

  cmp_mem(rx->iov_base, data->iov_base, rx->iov_len,
          "%s: Received data matches", cur_test);

  rxc->iov_ptr++;
  if( rxc->iov_ptr >= rxc->zcr.iovcnt )
    zft_zc_recv_done(rxc->zocket, &rxc->zcr);

  return 0;
}


int tst_queue_alternative(struct zft* ts, zf_althandle althandle,
                          const struct iovec* iov, int iov_cnt,
                          int flags)
{
  int rc;

  rc = zft_alternatives_queue(ts, althandle, iov, iov_cnt, flags);
  while( rc == -EAGAIN || rc == -EBUSY ){ 
    zf_reactor_perform(ctx.stack);
    rc = zft_alternatives_queue(ts, althandle, iov, iov_cnt, flags);
  }

  return rc;
}


int tst_zf_alternatives_send(struct zf_stack* stack, 
                             zf_althandle althandle)
{
  int rc;

  rc = zf_alternatives_send(stack, althandle);
  while( rc == -EBUSY ){ 
    zf_reactor_perform(ctx.stack);
    rc = zf_alternatives_send(stack, althandle);
  }

  return rc;
}


/* Simplest possible test: queue data on an alternative, send it, and
 * verify its arrival. */
static int test_simple(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[1], 1, 0));
  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[1]));

  return 0;
}


/* Simple segmenting test: queue data on an alternative, send it, and
 * verify its arrival. */
static int test_segment(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[4], 1, 0));
  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  int n_segs = (iovs[4].iov_len + 1460 - 1) / 1460;
  for( int i = 0; i < n_segs; i++ ) {
    struct iovec iov = {
      .iov_base = (char*)iovs[4].iov_base + (i * 1460),
      .iov_len = (i == n_segs - 1) ? iovs[4].iov_len % 1460 : 1460
    };
    ZF_TRY_RETURN(verify_data(&ctx.l, &iov));
  }

  return 0;
}


/* Send some normal data and then send using an alternative. */
static int test_normal_first(void)
{
  ZF_TRY_RETURN(zft_send(ctx.c.zocket, &iovs[0], 1, 0));
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[1], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[0]));
  ZF_TRY_RETURN(verify_no_data(&ctx.l));
  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[1]));
  ZF_TRY_RETURN(zft_send(ctx.c.zocket, &iovs[2], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[2]));

  return 0;
}


/* A series of 10 sends, all using alternatives. This checks that the
 * main sequence number is updated correctly when an alternative is
 * sent. */
static int test_10x(void)
{
  int i;

  for(i=0; i<10; i++) {
    ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                        &iovs[0], 1, 0));
    ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[1],
                                        &iovs[1], 1, 0));
    ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[2],
                                        &iovs[2], 1, 0));

    ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[i % 3]));
    for( int j = 0; j < 3; ++j )
      if( j != (i % 3) )
        ZF_TRY_RETURN(zf_alternatives_cancel(ctx.stack, ctx.alts[j]));
  }

  for(i=0; i<10; i++) {
    ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[i % 3]));
  }
  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  return 0;
}


/* In this test, data is received on a socket while it has an outgoing
 * packet queued in an alternative. This causes the TCP ACK to go
 * backwards. We check here that the connection is still usable in
 * both directions afterwards. */
static int test_receive(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[0], 1, 0));
  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  ZF_TRY_RETURN(zft_send(ctx.l.zocket, &iovs[1], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.c, &iovs[1]));

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[0]));

  ZF_TRY_RETURN(zft_send(ctx.c.zocket, &iovs[2], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[2]));

  ZF_TRY_RETURN(zft_send(ctx.l.zocket, &iovs[2], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.c, &iovs[2]));

  return 0;
}


/* Queue multiple packets on an alternative before sending it. */
static int test_multiple_packets(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[0], 1, 0));
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[1], 1, 0));
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[2], 1, 0));

  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[0]));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[1]));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[2]));
  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  return 0;
}


static void verify_no_alternatives(void) 
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, ctx.stack);

  /* Alternatives may still be draining; give them time to complete */
  zsleep(ctx.stack, 50000);

  for( int i = 0; i < zf_stack::MAX_ALTERNATIVES; i++ ) {
    cmp_ok(sti->alt[i].is_allocated, "==", 0,
           "%s: alt %d is free", cur_test);
  }

  for( int i = 0; i < zf_stack::MAX_ALTERNATIVES; i++ ) {
    cmp_ok(sti->alt[i].n_queued_packets, "==", 0,
           "%s: alt %d has no data", cur_test, i);
  }
}


/* Call zf_alternatives_release() while data is queued. */
static int test_free_while_queued(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0], 
                                      &iovs[0], 1, 0));
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[1], 
                                      &iovs[1], 1, 0));
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[2], 
                                      &iovs[2], 1, 0));

  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  for( int i = 0; i < NA; ++i )
    zf_alternatives_release(ctx.stack, ctx.alts[i]);

  verify_no_alternatives();

  return 0;
}


/* Try to send an alternative while there is unsent data on the
 * queue. */
static int test_sendq_nonempty(void)
{
  ZF_TRY_RETURN(zft_alternatives_queue(ctx.c.zocket, ctx.alts[0], 
                                       &iovs[0], 1, 0));

  /* Put some data on the send queue by reducing the cwnd to 0
   * temporarily so it doesn't go out on the wire. */

  struct tcp_pcb* pcb = &((struct zf_tcp *)ctx.c.zocket)->pcb;
  int old_cwnd = pcb->cwnd;
  pcb->cwnd = 0;
  tcp_fix_fast_send_length(pcb);

  ZF_TRY_RETURN(zft_send(ctx.c.zocket, &iovs[3], 1, 0));

  pcb->cwnd = old_cwnd;
  tcp_fix_fast_send_length(pcb);

  /* Now check that sending the alt fails with -EINVAL. */

  int rc = zf_alternatives_send(ctx.stack, ctx.alts[0]);
  cmp_ok(rc, "==", -EINVAL,
         "%s: send_alternative failed as expected", cur_test);

  return 0;
}


/* Send data using alternatives and verify that this can make the
 * socket become non-writable. */
static int test_writability(void)
{
  struct zf_waitable* w = zft_to_waitable(ctx.c.zocket);
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ctx.c.zocket);

  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0], 
                                      &iovs[3], 1, 0));

  cmp_ok(tcp_tx_advertise_space(tcp), "==", 1,
         "%s: zocket is writeable", cur_test);
  cmp_ok(w->readiness_mask, "&", EPOLLOUT,
         "%s: muxer agrees that zocket is writeable", cur_test);

  tcp->pcb.snd_buf_advertisement_threshold = tcp->pcb.snd_buf - 1;

  ZF_TRY_RETURN(zf_alternatives_send(ctx.stack, ctx.alts[0]));

  cmp_ok(tcp_tx_advertise_space(tcp), "==", 0,
         "%s: zocket is no longer writeable", cur_test);
  cmp_ok(~w->readiness_mask, "&", EPOLLOUT,
         "%s: muxer agrees that zocket is no longer writeable", cur_test);

  return 0;
}


/* Test that alternative queues are rebuilt when data is received. */
static int test_rebuild(void)
{
  int old_threshold = ctx.stack->tcp_alt_ack_rewind;
  
  /* Set the threshold to zero, so that any queued data will trigger a
   * rebuild */
  ctx.stack->tcp_alt_ack_rewind = 0;

  /* Queue some outgoing data on the alternatives. */

  ZF_TRY_RETURN(zft_alternatives_queue(ctx.c.zocket, ctx.alts[0], 
                                       &iovs[0], 1, 0));

  ZF_TRY_RETURN(zft_alternatives_queue(ctx.c.zocket, ctx.alts[1], 
                                       &iovs[1], 1, 0));

  ZF_TRY_RETURN(zft_alternatives_queue(ctx.c.zocket, ctx.alts[0], 
                                       &iovs[0], 1, 0));

  int first_ack = ctx.stack->tcp_alt_first_ack[0];

  /* Now receive some data, which will trigger a rebuild. */
  ZF_TRY_RETURN(zft_send(ctx.l.zocket, &iovs[1], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.c, &iovs[1]));

  zsleep(ctx.stack, 1000);

  cmp_ok(first_ack, "!=", ctx.stack->tcp_alt_first_ack[0],
         "%s: alternative was rebuilt", cur_test);

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[0]));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[0]));

  ctx.stack->tcp_alt_ack_rewind = old_threshold;

  return 0;
}


/* Test that alts don't get rebuilt if the amount of queued data is
 * less than the tcp_alt_ack_rewind threshold. */
static int test_rebuild_threshold(void)
{

  ZF_TRY_RETURN(zft_alternatives_queue(ctx.c.zocket, ctx.alts[0], 
                                       &iovs[0], 1, 0));

  cmp_ok(iovs[0].iov_len, "<", ctx.stack->tcp_alt_ack_rewind,
         "%s: Queued data is below the threshold", cur_test);

  int first_ack = ctx.stack->tcp_alt_first_ack[0];

  ZF_TRY_RETURN(zft_send(ctx.l.zocket, &iovs[1], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.c, &iovs[1]));

  zsleep(ctx.stack, 1000);

  cmp_ok(first_ack, "==", ctx.stack->tcp_alt_first_ack[0],
         "%s: alternative was not rebuilt", cur_test);

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[0]));

  return 0;
}


/* Test that we can send an alt that has already been sent. */
static int test_send_twice(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[1], 1, 0));
  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[1]));

  return 0;
}


/* Test that we can cancel an alt that has already been sent. */
static int test_send_then_cancel(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[1], 1, 0));
  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(zf_alternatives_cancel(ctx.stack, ctx.alts[0]));

  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[1]));

  return 0;
}


/* Test the Medford-specific buffering model (in isolation) */
static int test_buffer_model_medford(void)
{
  struct zf_alt_buffer_model bm;

  /* Ensure we have known values for the buffer settings. */
  struct zf_attr local_attr;

  local_attr.alt_count = 4;
  local_attr.alt_buf_size = 4096; /* note that ZF adds one switch-buffer per
                                   * alt for per-vfifo overhead */

  zf_altbm_init(&bm, reinterpret_cast<zf_stack_impl*>(ctx.stack), 0, &local_attr);

  /* Initially all the alts consume 1 buffer each, with all the
   * hardware pointers at the start of that buffer so none of it is
   * lost. So, the available space in an alt is the total space, minus
   * 1 buffer for each _other_ alt, minus 1 word for the per-packet
   * overhead of the next packet we send. */

  cmp_ok(zf_altbm_bytes_free(&bm, 0), "==", 6624,
         "%s: free space is initially correct", cur_test);

  /* A 736 byte packet will occupy exactly 1.5 buffers. */

  cmp_ok(zf_altbm_send_packet(&bm, 0, 736), "==", true,
         "%s: packet sent successfully", cur_test);

  /* The free space should have decreased to match. */

  cmp_ok(zf_altbm_bytes_free(&bm, 0), "==", 5856,
         "%s: free space is correct after sending packet", cur_test);

  /* Now send the alt. This leaves the head/tail pointers pointing
   * half way through a buffer, so the apparent free space should be
   * correspondingly less. */

  zf_altbm_alt_reset(&bm, 0);

  cmp_ok(zf_altbm_bytes_free(&bm, 0), "==", 6368,
         "%s: free space is correct after sending", cur_test);

  /* We should not be able to send a packet larger than the free
   * space. */

  cmp_ok(zf_altbm_send_packet(&bm, 0, 6369), "==", false,
         "%s: oversize packet rejected correctly", cur_test);

  /* A packet that exactly fills the free space should be OK. */

  cmp_ok(zf_altbm_send_packet(&bm, 0, 6368), "==", true,
         "%s: max size packet accepted correctly", cur_test);

  /* Now there should be no free space at all. */
  cmp_ok(zf_altbm_bytes_free(&bm, 0), "==", 0,
         "%s: free space is zero", cur_test);

  /* On resetting we should be back to the maximum available space. */
  zf_altbm_alt_reset(&bm, 0);
  cmp_ok(zf_altbm_bytes_free(&bm, 0), "==", 6624,
         "%s: free space is initially correct", cur_test);

  /* Now send a packet which stops one word short of the end of a
   * buffer. In this case the hardware will allocate another buffer to
   * the alt, which should show up as a reduction in the space
   * available to the other alts. */

  cmp_ok(zf_altbm_send_packet(&bm, 0, 448), "==", true,
         "%s: just-short packet accepted correctly", cur_test);
  
  cmp_ok(zf_altbm_bytes_free(&bm, 0), "==", 6144,
         "%s: free space is initially correct", cur_test);

  cmp_ok(zf_altbm_bytes_free(&bm, 1), "==", 6112,
         "%s: free space is initially correct", cur_test);

  return 0;
}


/* Test that we react well to the caller trying to send too much
 * data. Note that this is distinct from test_per_packet_overhead(),
 * which tests that we have at least a known minimum amount of space.
 * This test verifies that we behave sensibly when we hit the _real_
 * limit, which may be some way beyond the known minimum. */
static int test_buffer_model(void)
{
  unsigned n_packets = 0;
  int rv;

  /* Increase the congestion window temporarily. */
  struct tcp_pcb* pcb = &((struct zf_tcp *)ctx.c.zocket)->pcb;
  int old_cwnd = pcb->cwnd;
  pcb->cwnd = MAX_CWND;

  /* If alt_buf_size is too large then this test will run out of
   * window space before hitting the buffer size limit. */
  cmp_ok(ctx.attr->alt_buf_size, "<=", 16384,
         "%s: alt_buf_size is small enough for this test", cur_test);

  do {
    rv = tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                               &iovs[3], 1, 0);
    if( rv == 0 )
      n_packets++;
  } while( (n_packets < 100) && (rv != -ENOBUFS) );

  /* First check that we weren't allowed to send a stupid number of
   * packets. */

  cmp_ok(n_packets, "<", 100,
         "%s: stack limited our transmission", cur_test);

  /* Now check that all the data we sent is received correctly. */

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  for( unsigned i = 0; i < n_packets; i++ ) {
    ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[3]));
  }

  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  pcb->cwnd = old_cwnd;

  return 0;
}


/* Send normally while data is queued on an alternative, then try to
 * send the alternative. Verify that this fails with -EINVAL. */
static int test_send_while_queued(void)
{
  ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[0],
                                      &iovs[0], 1, 0));
  ZF_TRY_RETURN(verify_no_data(&ctx.l));
  ZF_TRY_RETURN(zft_send(ctx.c.zocket, &iovs[1], 1, 0));
  ZF_TRY_RETURN(verify_data(&ctx.l, &iovs[1]));

  cmp_ok(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]), "==", -EINVAL,
         "%s: alt send failed as expected", cur_test);

  return 0;
}


/* Test that it is possible to queue at least the number of bytes
 * requested via the alt_buf_size attribute, taking into account
 * per-packet overhead via ef_vi_transmit_alt_usage().
 *
 * There are two variants of this test using different numbers of
 * alts, to verify that non-per-packet overhead is not accounted for
 * by this method. */
static int test_per_packet_overhead(int n_alts)
{
  unsigned alt_buf_size = ctx.attr->alt_buf_size;
  struct ef_vi_transmit_alt_overhead ovinfo;
  char tmp[MAX_PKT_SIZE];
  struct iovec iov;

  /* Increase the congestion window temporarily. */
  struct tcp_pcb* pcb = &((struct zf_tcp *)ctx.c.zocket)->pcb;
  int old_cwnd = pcb->cwnd;
  pcb->cwnd = MAX_CWND;

  iov.iov_base = tmp;

  memset(tmp, 0, sizeof(tmp));

  zf_alternatives_query_overhead_tcp(ctx.c.zocket, &ovinfo);

  /* First fill the available buffering exactly. */

  unsigned min_pkt_usage = ef_vi_transmit_alt_usage(&ovinfo, 0);
  unsigned free_space = alt_buf_size;
  unsigned total_payload = 0; /* total payload sent into alt 0 */
  int alt_id = 0;

  while( free_space > min_pkt_usage )
  {
    /* Choose the largest packet size which should fit into the
     * remaining space. */

    unsigned pkt_size = MAX_PKT_SIZE;
    while( ef_vi_transmit_alt_usage(&ovinfo, pkt_size) > free_space )
      pkt_size--;

    /* Now send the packet. */

    iov.iov_len = pkt_size;
    ZF_TRY_RETURN(tst_queue_alternative(ctx.c.zocket, ctx.alts[alt_id],
                                        &iov, 1, 0));

    /* Account for its buffer usage. */

    if( alt_id == 0 )
      total_payload += pkt_size;

    free_space -= ef_vi_transmit_alt_usage(&ovinfo, pkt_size);

    /* Move on to the next alt. */

    alt_id++;
    if( alt_id >= n_alts )
      alt_id = 0;
  }

  cmp_ok(free_space, "==", 0,
         "%s: filled the buffers exactly", cur_test);

  /* Now send alt 0 and verify that the expected amount of data is
   * received. */

  ZF_TRY_RETURN(tst_zf_alternatives_send(ctx.stack, ctx.alts[0]));

  unsigned verified_payload = 0;

  while( verified_payload < total_payload ) {

    unsigned remaining = total_payload - verified_payload;
    unsigned amount = remaining;

    if( amount > MAX_PKT_SIZE )
      amount = MAX_PKT_SIZE;

    iov.iov_len = amount;
    ZF_TRY_RETURN(verify_data(&ctx.l, &iov));

    verified_payload += amount;
  }

  ZF_TRY_RETURN(verify_no_data(&ctx.l));

  pcb->cwnd = old_cwnd;

  return 0;
}


static int test_per_packet_overhead_one(void)
{
  return test_per_packet_overhead(1);
}


static int test_per_packet_overhead_all(void)
{
  return test_per_packet_overhead(NA);
}


static int test_fw_variant(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY_RETURN(zf_attr_alloc(&attr));

  zf_emu_set_fw_variant(MC_CMD_GET_CAPABILITIES_OUT_TXDP);
  rc = zf_stack_alloc(attr, &stack);
  cmp_ok(rc, "!=", 0, "full featured FW");
  if( rc == 0 )
    zf_stack_free(stack);

  zf_emu_set_fw_variant(MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY);
  rc = zf_stack_alloc(attr, &stack);
  cmp_ok(rc, "==", 0, "low latency FW");
  if( rc == 0 )
    zf_stack_free(stack);

  zf_emu_set_fw_variant(MC_CMD_GET_CAPABILITIES_OUT_TXDP_RULES_ENGINE);
  rc = zf_stack_alloc(attr, &stack);
  cmp_ok(rc, "!=", 0, "Rules Engine FW");
  if( rc == 0 )
    zf_stack_free(stack);

  zf_attr_free(attr);

  return 0;
}


#define TEST(a) { #a , a }

static struct {
  const char *name;
  int (*test)(void);
} tests[] = {
  TEST(test_simple),
  TEST(test_segment),
  TEST(test_10x),
  TEST(test_normal_first),
  TEST(test_receive),
  TEST(test_multiple_packets),
  TEST(test_free_while_queued),
  TEST(test_sendq_nonempty),
  TEST(test_rebuild),
  TEST(test_rebuild_threshold),
  TEST(test_writability),
  TEST(test_send_twice),
  TEST(test_send_then_cancel),
  TEST(test_buffer_model_medford),
  TEST(test_buffer_model),
  TEST(test_send_while_queued),
  TEST(test_per_packet_overhead_one),
  TEST(test_per_packet_overhead_all),
};


static int test(void)
{
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY_RETURN(init_stack(&stack, &attr));
  memset(&ctx, 0, sizeof(ctx));

  ctx.stack = stack;
  ctx.attr = attr;

  ctx.bind_addr.sin_family = AF_INET;
  ctx.bind_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  ctx.bind_addr.sin_port = htons(0);

  for( unsigned i = 0; i < sizeof(tests)/sizeof(tests[0]); i++ ) {
    cur_test = tests[i].name;
    ZF_TRY_RETURN(init_sockets());
    ZF_TRY_RETURN(tests[i].test());
    ZF_TRY_RETURN(fini_sockets());
  }

  ZF_TRY_RETURN(fini_stack(stack, attr));

  ZF_TRY_RETURN(test_fw_variant());

  done_testing();

  return 0;
}


int main(void)
{
  int rc;

  ZF_TRY_RETURN(zf_init());
  rc = test();
  ZF_TRY_RETURN(zf_deinit());

  return rc;
}

