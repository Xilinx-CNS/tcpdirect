/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF: epoll support
 */

#include <zf/zf.h>
#include <zf_internal/shim/shim.h>

#include <sys/epoll.h>
#include <unordered_map>
using namespace std;


/* Flags on this epoll object.
 * Currently, we do not support mixture of OS and ZF objects in one
 * epoll set.*/
typedef uint8_t zfss_muxer_flag;
static const zfss_muxer_flag ZFSS_MUXER_FLAG_ZF = 0x1;
static const zfss_muxer_flag ZFSS_MUXER_FLAG_OS = 0x2;

typedef
  std::unordered_map<struct zf_waitable*, epoll_data_t>
zfss_waitable_map;

struct zfss_muxer {
  struct zfss_file file;
  struct zf_muxer_set* muxer;

  /* Mapping between epoll_event.data passed to muxer and the real
   * waitable. */
  zfss_waitable_map map;

  zfss_muxer_flag flags;
};

static struct zfss_muxer* zfss_fd_table_get_muxer(int fd)
{
  struct zfss_file* file = zfss_fd_table_get(fd);
  if( file == NULL )
    return NULL;
  return ZF_CONTAINER(struct zfss_muxer, file, file);
}


static int zfss_epoll_close(struct zfss_file* file)
{
  struct zfss_muxer* mux = ZF_CONTAINER(struct zfss_muxer, file, file);

  zf_muxer_free(mux->muxer);
  mux->map.~zfss_waitable_map();
  return 0;
}


static int zfss_epoll_create(int flags);
ZF_INTERCEPT(int, epoll_create1, int flags)
{
  return zfss_epoll_create(flags);
}
ZF_INTERCEPT(int, epoll_create, int size)
{
  return zfss_epoll_create(0);
}
static int zfss_epoll_create(int flags)
{
  int saved_errno = errno;
  int fd = zfss_sys_epoll_create1(flags);

  /* Initialise the library if we haven't done so already. */
  if( fd < 0 || ! zfss_init_real() || ! zfss_enter_lib() )
    return fd;

  struct zfss_muxer* mux = (struct zfss_muxer*)
                           malloc(sizeof(struct zfss_muxer));
  new (&mux->map) zfss_waitable_map();
  int rc = zf_muxer_alloc(stack, &mux->muxer);
  zfss_exit_lib();

  if( rc < 0 ) {
    free(mux);
    RET_WITH_ERRNO(-rc);
  }

  mux->flags = 0;
  mux->file.close = zfss_epoll_close;
  zfss_fd_table_insert(fd, &mux->file);
  errno = saved_errno;
  zf_log_ss_info(stack, "::%s() -> %d\n", __func__, fd);
  return fd;
}


ZF_INTERCEPT(int, epoll_ctl, int epfd, int op, int fd, struct epoll_event *event)
{
  int saved_errno = errno;
  struct zfss_muxer* mux = zfss_fd_table_get_muxer(epfd);
  struct zfss_socket* sock = zfss_fd_table_get_sock(fd);

  if( mux == NULL || sock == NULL || sock->ops->waitables == NULL ||
      ! zfss_enter_lib() ) {
    if( mux != NULL )
      mux->flags |= ZFSS_MUXER_FLAG_OS;
    return zfss_sys_epoll_ctl(epfd, op, fd, event);
  }
  zf_log_ss_info(stack, "::%s(%d, %s, %d, ...)\n", __func__, epfd,
                  op == EPOLL_CTL_ADD ? "add" : op == EPOLL_CTL_MOD ?
                  "mod" : op == EPOLL_CTL_DEL ? "del" : "unknown", fd);

  struct zfss_waitable wait[SHIM_SOCK_WAITABLES_MAX];
  int n = sock->ops->waitables(sock, wait);
  int rc = 0;
  epoll_data_t data = event->data;
  /* EPOLLHUP and EPOLLERR are supposed to be always on */
  event->events |= EPOLLHUP | EPOLLERR;

  switch( op ) {
    case EPOLL_CTL_ADD:
      for( int i = 0; i < n; i++ ) {
        if( event->events & wait[i].ev ) {
          mux->map[wait[i].w] = data;
          event->data.ptr = wait[i].w;
          rc = __zf_muxer_add(mux->muxer, wait[i].w, event);
          if( rc < 0 )
            break;
        }
      }
      break;
    case EPOLL_CTL_DEL:
      for( int i = 0; i < n; i++ )
        zf_muxer_del(wait[i].w);
      break;
    case EPOLL_CTL_MOD:
      for( int i = 0; i < n; i++ ) {
        if( event->events & wait[i].ev ) {
          mux->map[wait[i].w] = data;
          event->data.ptr = wait[i].w;
          rc = zf_muxer_mod(wait[i].w, event);
          if( rc < 0 ) {
            rc = __zf_muxer_add(mux->muxer, wait[i].w, event);
            if( rc < 0 )
              break;
          }
        }
        else {
          zf_muxer_del(wait[i].w);
        }
      }
      break;
    default:
      rc = -EINVAL;
  }
  zfss_exit_lib();
  zf_log_ss_info(stack, "::%s(%d, %d, %d, ...) -> %d\n",
                  __func__, epfd, op, fd, rc);
  if( rc < 0 )
    RET_WITH_ERRNO(-rc);

  mux->flags |= ZFSS_MUXER_FLAG_ZF;
  errno = saved_errno;
  return rc;
}

ZF_INTERCEPT(int, epoll_wait, int epfd, struct epoll_event *events,
             int maxevents, int timeout)
{
  int saved_errno = errno;
  struct zfss_muxer* mux = zfss_fd_table_get_muxer(epfd);
  int rc;
  int64_t timeout_ns;

  if( mux == NULL || (mux->flags & ZFSS_MUXER_FLAG_OS) ||
      ! zfss_enter_lib() ) {
    return zfss_sys_epoll_wait(epfd, events, maxevents, timeout);
  }


  /* Socket tester uses epoll_wait() with the empty set as a way to call
   * reactor when there is nothing to do.  Let's suppress these messages. */
  if( mux->flags & ZFSS_MUXER_FLAG_ZF ) {
    zf_log_ss_info(stack, "::%s(%d, maxevents=%d, timeout_ms=%d)\n",
                    __func__, epfd, maxevents, timeout);
  }
  else {
    zf_log_ss_trace(stack, "::%s(%d(empty set), timeout_ms=%d)\n",
                    __func__, epfd, timeout);
  }

#define MAX_LOCAL_EVENTS 10
  struct epoll_event local_events[MAX_LOCAL_EVENTS * SHIM_SOCK_WAITABLES_MAX];
  struct epoll_event *events1 = NULL;

  /* unordered_map does not accept epoll_data_t as a key type, so let's use
   * epoll_data_t.u64 */
  std::unordered_map<uint64_t, struct epoll_event*> data2ev;
  int j = 0;

  /* Prepare a larger storage for events, because we have more waitables
   * than sockets. */
  if( maxevents <= MAX_LOCAL_EVENTS ) {
    events1 = local_events;
  }
  else {
    events1 = (struct epoll_event*)malloc(sizeof(struct epoll_event) *
                                          maxevents *
                                          SHIM_SOCK_WAITABLES_MAX);
    if( events1 == NULL ) {
      rc = -ENOMEM;
      goto out;
    }
  }

  /* epoll_wait() takes timeouts in milliseconds, whereas zf_muxer_wait() takes
   * them in nanoseconds. */
  timeout_ns = (timeout > 0) ? (int64_t) timeout * 1000000 : timeout;

  /* Call the real muxer */
  rc = zf_muxer_wait(mux->muxer, events1,
                     maxevents * SHIM_SOCK_WAITABLES_MAX,
                     timeout_ns);
  if( rc < 0 )
    goto out;

  for( int i = 0; i < rc; i++ ) {
    /* Replace data by user-provided value. */
    struct zf_waitable* w = (struct zf_waitable*)events1[i].data.ptr;
    epoll_data_t data = mux->map[w];

    if( data2ev.find(data.u64) != data2ev.end() ) {
      data2ev[data.u64]->events |= events1[i].events;
    }
    else if( j < maxevents ) {
      events[j].data = data;
      events[j].events = events1[i].events;
      data2ev[data.u64] = &(events[j]);
      j++;
    }
    /* else we ignore events because of maxevents limitation */

    /* Re-arm level-triggered event request. */
    const struct epoll_event* ev = zf_waitable_event(w);
    if( ! (ev->events & EPOLLET) )
      zf_muxer_mod(w, ev);
  }
  rc = j;
 out:
  zfss_exit_lib();
  if( mux->flags & ZFSS_MUXER_FLAG_ZF ) {
    zf_log_ss_info(stack, "::%s(%d, maxevents=%d, timeout_ms=%d) -> %d\n",
                    __func__, epfd, maxevents, timeout, rc);
  }
  else {
    zf_log_ss_trace(stack, "::%s(%d(empty set), timeout_ms=%d) -> %d\n",
                    __func__, epfd, timeout, rc);
  }
  if( rc < 0 )
    RET_WITH_ERRNO(-rc);
  if( events1 != NULL && events1 != local_events )
    free(events1);
  errno = saved_errno;
  return rc;
}
