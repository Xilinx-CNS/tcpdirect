/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF.
 */

#include <zf/zf.h>
#include <zf_internal/shim/shim.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/timekeeping.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <pthread.h>

static int zfss_process_alarm(void);


/* Prevent re-entry into the library within each thread */
static __thread bool in_lib = false;

/* Prevent synchronous access by multiple threads. We don't care about
 * performance, so we don't need anything more granular than a big lock
 * around library entry points. */
static pthread_mutex_t zfss_lock = PTHREAD_MUTEX_INITIALIZER;

/* Keep track of poll events so that blocking operations can respond to
 * events that were handled by other threads. */
static uint32_t zfss_poll_events;

static struct {
  bool alarm_primed;
  uint64_t alarm_expiry_time;
} process_context = {
  .alarm_primed = 0,
  .alarm_expiry_time = 0,
};

bool zfss_enter_lib(void)
{
  if( in_lib )
    return false;
  pthread_mutex_lock(&zfss_lock);
  in_lib = true;
  return true;
}

void zfss_exit_lib(void)
{
  pthread_mutex_unlock(&zfss_lock);
  zf_assert(in_lib);
  in_lib = false;
}


/* In order to be backwards compatible with older versions of ZF, we link
 * against zf_reactor_perform_attr weakly and fall back to
 * zf_reactor_perform if it is unavailable. */
__attribute__((weak))
int zf_reactor_perform_attr(struct zf_stack* stack, const struct zf_attr* attr);


static zf_frc zfss_last_poll;

/* Processes all the events that have arrived and then returns without waiting
 * for more.
 *
 * To wait for an event, use zfss_block_on_stack instead. */
static inline int zfss_stack_poll(zf_stack* stack)
{
  int rc = 0;

  if( zf_reactor_perform_attr )
    while( zf_reactor_perform_attr(stack, attr_short_poll) != 0 )
      rc = 1;
  else
    while( zf_reactor_perform(stack) != 0 )
      rc = 1;
  zfss_last_poll = zf_frc64();
  zfss_poll_events += rc;
  return rc;
}

int zfss_stack_poll(void)
{
  return zfss_stack_poll(stack);
}

static inline void zfss_stack_poll_if_behind(zf_stack* stack)
{
  const int POLL_IF_BEHIND_THRESHOLD_MS = 10;
  uint64_t frc_threshold = zf_timekeeping_ms2frc(&stack->times.time,
                                                 POLL_IF_BEHIND_THRESHOLD_MS);
  if( zf_frc64() - zfss_last_poll > frc_threshold )
    zfss_stack_poll(stack);
}

struct zfss_socket* zfss_fd_table_get_sock(int fd)
{
  struct zfss_file* file = zfss_fd_table_get(fd);
  if( file == NULL )
    return NULL;
  return ZF_CONTAINER(struct zfss_socket, file, file);
}


template <typename APICall, APICall real_api_call>
struct ShimBlockingHelper {
  static inline void poll(zf_stack* st, int fd) {
  }
};


/* We use templated classes to generate the boilerplate for shimming each
 * sockets API call that takes an fd. */

/* Given the name of a sockets-API call, we need to deduce its return type and
 * the types of its arguments so that we can emit a wrapper that matches its
 * signature.  This requires two stages: the first is this parent template,
 * which is parameterised by the types and addresses of the real API function
 * and of the corresponding ZF implementation function. */
template <typename APICall, APICall real_api_call, typename ShimCall,
          ShimCall shim_call>
struct ShimSockCall;


/* Contains set of functions to print fd call argument(s) */
struct FdArgPrint {
  static void p(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    zf_log_ss_info(fmt, va);
    va_end(va);
  }
  static bool validate_ptr(const void* x) {
    if( x == 0 )
      p("(null)");
    return x != 0;
  }
  /* Below list of functions printing different argument types */
  static void f(int x)
    { p("%d", x); }
  static void f(unsigned x)
    { p("0x%x", x); }
  static void f(size_t x)
    { p("%d", x); }
  /* Generic pointer specialization: provide specific one to print more details */
  static void f(const void* x)
    { p("(*)%p", x); }
  static void f(const sockaddr* x)
    {   if( ! validate_ptr(x) ) return;
        p("%s:%d", inet_ntoa(((const sockaddr_in*)x)->sin_addr),
                   htons(((const sockaddr_in*)x)->sin_port)); }
  static void f(const timespec* x) {
    if( validate_ptr(x) ) p("%d.%6d", x->tv_sec, x->tv_nsec); }
  /* Special case for iovec which is specified by two arguments */
  static void f(const iovec* x, int iov_cnt)
  {
    if( ! validate_ptr(x) )
      return;
    p("[ ");
    for( int i = 0; i < iov_cnt; ++i ) {
      p("%p/%lu ", x[i].iov_base, x[i].iov_len);
    }
    p("]/%d", iov_cnt);
  }
  /* Hitting this symbol indicates missing specialization for
   * the given argument type(s) */
  struct NoMatch {};
  static NoMatch f(...) __attribute__((error(
    "how to print this parameter? - please overload f()")));
};

/* Prints argument values on return of fd call
 * E.g. non const pointers now are supposed to be filled with data
 */
struct FdArgRetPrint : public FdArgPrint {
  using FdArgPrint::f; /*< Bring in overloads from FdArgPrint */
  static void f(int* x)
    { if( validate_ptr(x) ) p("[%d]", *x); }
  static void f(unsigned * x)
    { if( validate_ptr(x) ) p("[0x%x]", *x); }
  static void f(unsigned long* x)
    { if( validate_ptr(x) ) p("[0x%lx]", *x); }
};


/* Procesess argument list from left to right,
 * taking one or two arguments at a time depending on the best match to F::f()
 * Uses F::f to print argument(s) at the head and moves on to the following ones
 * until all are processed.
 */
template <typename... Args>
struct XFdPrint;
/* Terminal implementation for empty argument list */
template <typename F>
struct XFdPrint<F> {
  void operator()() {}
};
/* Terminal implementation for single argument */
template <typename F, typename T>
struct XFdPrint<F, T> {
  void operator()(T a)
    { F::f(a); }
};
/* Recursive implementation for two or more arguments */
template <typename F, typename T, typename U, typename... Args>
struct XFdPrint<F, T, U, Args...> {
  static constexpr const char* sep[2] { "", ", " };
  /* This is wrapper type as void is not a valid type of argument to funcion*/
  template <typename Z>
  struct Select {};
  /* Invoke dual argument function, and follow on */
  static void fwd(const Select<void>&, T t, U u, Args... args) {
    F::f(t,u);
    F::p("%s", sep[sizeof...(Args) != 0]);
    XFdPrint<F, Args...>()(args...);
  }
  /* No match for 2 arg function, Invoke 1 argument function and follow on */
  static void fwd(const Select<typename F::NoMatch>&, T t, U u, Args... args) {
    F::f(t);
    F::p("%s", sep[1]);
    XFdPrint<F, U, Args...>()(u, args...);
  }
  void operator()(T t, U u, Args... args) {
    /* Depending on whether specialisation for two argument F::f() matches
     * invoke respective implementation of fwd */
    fwd(Select<decltype(F::f(t,u))>{}, t, u, args...);
  }
};


/* The second stage is where the actual work is done.  It specialises the
 * parent template and splits apart the signatures into their return types and
 * argument lists, and emits the thunk that dispatches the call either to the
 * ZF implementation or else to the real API call. */
template<typename Ret, typename... Args,
         Ret (**real_api_call)(int, Args...),
         Ret (*zfss_socket_ops::*shim_call)(struct zfss_socket*, Args...)>
struct ShimSockCall<Ret (**)(int fd, Args...), real_api_call,
                    Ret (*zfss_socket_ops::*)(struct zfss_socket*, Args...),
                    shim_call>
{
    static Ret thunk(int fd, Args... args)
    {
        struct zfss_socket* sock;
        int saved_errno = errno;

        int rc1 = zfss_process_alarm();
        if( rc1 < 0 )
          RET_WITH_ERRNO(-rc1);

        if( ! zfss_enter_lib() ) {
          /* We are re-entering the shim via a libc symbol.  Logging can
           * trigger this.  To avoid overflowing the stack, we must be careful
           * here not to re-enter again, so we just make the syscall.  This
           * means that re-entering via a call on a shimmed fd is invalid, but
           * we can't assert this fact because that could result in logging...
           */
          errno = saved_errno;
          return (*real_api_call)(fd, args...);
        }

        if( (sock = zfss_fd_table_get_sock(fd)) != NULL ) {
          /* If the app calls into the shim after not having done so for a long
           * time, bring things up to date before servicing the call. */
          zfss_stack_poll_if_behind(stack);

          /* __PRETTY_FUNCTION__ is not pretty at all, but
           * typeid(*this).name() does not work in a static method. */

          zf_log_ss_info(stack, "%s(",
                          strstr(strstr(__PRETTY_FUNCTION__, "= &"), "::"));
          XFdPrint<FdArgPrint, int, Args...>()(fd, args...);
          zf_log_ss_info(NO_STACK, ")\n");
          Ret rc = (sock->ops->*shim_call)(sock, args...);
          zf_log_ss_info(stack,"%s(",
                          strstr(strstr(__PRETTY_FUNCTION__, "= &"), "::"));
          if( rc >= 0 )
            XFdPrint<FdArgRetPrint, int, Args...>()(fd, args...);
          else /* In case of error do not print garbage */
            XFdPrint<FdArgPrint, int, Args...>()(fd, args...);
          zf_log_ss_info(NO_STACK,") -> %d\n", (int)rc);
          if( rc == -EHOSTUNREACH ) {
            /* No route - perhaps wrong interface - case for handover.
             * ZF state should already have been freed,
             * now clear shim state */
            zf_log_ss_info(stack, "%s(%d, ...) - HANDOVER\n",
                            strstr(strstr(__PRETTY_FUNCTION__, "= &"), "::"),
                            fd);
            zfss_handover(fd);
            rc = -ENOSYS;
          }

          if( rc == -ENOSYS ) {
            /* Shim doesn't implement this; fall through to sockets API. */
          }
          else if( rc < 0 ) {
            /* Shim failed. */
            zfss_exit_lib();
            RET_WITH_ERRNO(-rc);
          }
          else {
            /* Shim succeeded. */
            zfss_stack_poll(stack);
            errno = saved_errno;
            zfss_exit_lib();
            return rc;
          }
        }

        if( zfss_init() ) {
          zfss_stack_poll(stack);
          /* Do poll descriptor untill following op
           * is ensured not to block making sure zf stack is progressed not
           * starved of CPU.
           * For blocking functions' specializations see below. */
          ShimBlockingHelper<decltype(real_api_call),real_api_call>::
            poll(stack, fd);
        }
        errno = saved_errno;
        int rc = (*real_api_call)(fd, args...);
        if( zfss_init() ) {
          zfss_stack_poll(stack);
        }
        zfss_exit_lib();
        return rc;
    }
};


/* We now have a template that we can instantiate for any API function to
 * generate a dispatcher thunk.  Having done so, we then need to define the
 * API symbol to point to the thunk.  This macro handles those two steps. */
#define ZF_INTERCEPT_FD_CALL(func)                                            \
  auto zfss_##func##_thunk = ShimSockCall<decltype(&zfss_sys_##func),         \
                                          &zfss_sys_##func,                   \
                                          decltype(&zfss_socket_ops::func),   \
                                          &zfss_socket_ops::func>::thunk;     \
                                                                              \
  /* Trampoline to the thunk. */                                              \
  asm ("  .section .text\n"                                                   \
       "  .global " #func "\n"                                                \
       #func ":\n"                                                            \
       "  mov zfss_" #func "_thunk@GOTPCREL(%rip), %rax\n"                    \
       "  mov (%rax), %rax\n"                                                 \
       "  jmp *%rax\n");


#define __IFF0(a)
#define __IFF1(a) a
#define __IFF(cond,a) __IFF##cond(a)
/* Based on condition leave or purge second operand */
#define IFF(cond,a) __IFF(cond,(a))


/* List of all calls to intercept with thunk */
#define FD_CALL_LIST(F) \
 F(bind) \
 F(connect) \
 F(listen) \
 F(accept) \
 F(shutdown) \
 F(getsockname) \
 F(getpeername) \
 F(getsockopt) \
 F(setsockopt) \
 F(recvmmsg) \
 F(recvmsg) \
 F(recvfrom) \
 F(recv) \
 F(read) \
 F(readv) \
 IFF(SHIM_SENDMMSG,F(sendmmsg)) \
 F(sendmsg) \
 F(sendto) \
 F(send) \
 F(write) \
 F(writev) \


/* generate real api entries for each symbol from the list */
FD_CALL_LIST(ZF_FIND_REAL_API_ENTRY)

/* ioctl() & fcntl() are declared with vararg parameters, so normal machinery
 * with ZF_SOCKET_OP, ZF_INTERCEPT_FD_CALL and even ZF_INTERCEPT
 * does not work. */
int (*zfss_sys_ioctl)(int fd, unsigned long request, void* arg);
int (*zfss_sys_fcntl)(int fd, int cmd, long arg);


struct ShimBlockingReadHelper {
  /* wait for alien fd to become readable, poll stack in the meantime,
   * without bogging down cpu */
  static inline void poll(zf_stack* st, int fd)
  {
      if( zfss_sys_fcntl(fd, F_GETFL, 0) & O_NONBLOCK )
        return;
      while( poll_once(fd) == 0 && zfss_init() )
        zfss_stack_poll(stack);
  }

  static inline int poll_once(int fd)
  {
    int rc;
    struct timespec timeout = {.tv_sec = 0, .tv_nsec = 100000};
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};

    pthread_mutex_unlock(&zfss_lock);
    rc = ppoll(&pfd, 1, &timeout, NULL);
    pthread_mutex_lock(&zfss_lock);

    return rc;
  }
};


/* creates instantiation of ShimBlockingHelper using implementation of
 * ShimBlockingReadHelper meant for read/recv functions */
#define ZF_GEN_BLOCKING_READ_HELPER(func) \
template<> \
struct ShimBlockingHelper<decltype(&zfss_sys_##func), &zfss_sys_##func> : \
  public ShimBlockingReadHelper { }; \


/* List of functions needing sorting out blocking on alien read */
#define FD_BLOCKING_READ_CALL_LIST(F) \
 F(recvmmsg) \
 F(recvmsg) \
 F(recvfrom) \
 F(recv) \
 F(read) \
 F(readv) \


/* Specialize blocking read helpers for the calls from the list */
FD_BLOCKING_READ_CALL_LIST(ZF_GEN_BLOCKING_READ_HELPER)


/* Generate thunks and sys call entry points,
 * use appropriate blocking call helper */
FD_CALL_LIST(ZF_INTERCEPT_FD_CALL)


extern "C" __attribute__((visibility("default"))) int
socket(int domain, int type, int protocol)
{
  /* We allocate a real socket.  This gets us an fd and means that, for parts
   * of the sockets API that we don't shim, there's a non-zero chance that
   * falling back to the syscall will actually appear to applications to work.
   * The downside is that it's unnecessarily slow. */
  int saved_errno = errno;

  /* Initialise the library if we haven't done so already. */
  if( domain != AF_INET || ! zfss_init_real() || ! zfss_enter_lib() )
    return zf_sys_socket(domain, type, protocol);

  struct zfss_socket* sock = NULL;
  int rc = zfss_create(domain, type, protocol, &sock);
  if( rc < 0 ) {
    zfss_exit_lib();
    RET_WITH_ERRNO(-rc);
  }

  errno = saved_errno;
  zfss_exit_lib();
  zf_log_ss_info(stack, "::%s(%s) -> %d\n", __func__,
                  type == SOCK_STREAM ? "TCP" : "UDP", rc);
  return rc;
}


static int zfss_sock_close(zfss_file* file)
{
  struct zfss_socket* sock = ZF_CONTAINER(struct zfss_socket, file, file);
  if( sock->waitable != NULL )
    zf_waitable_free(sock->waitable);
  return sock->ops->close(sock);
}


/* If we shim the requested type of socket, we create an instance of the shim
 * state for it and succeed.  If we do not shim the socket, we still succeed,
 * but *sock_out will be NULL. */
int zfss_create(int domain, int type, int protocol,
                struct zfss_socket** sock_out)
{
  struct zfss_socket* sock = *sock_out;
  int rc;

  int fd = zf_sys_socket(domain, type, protocol);
  if( fd < 0 )
    return fd;

  int nonblock = protocol & SOCK_NONBLOCK;
  protocol &=~ (SOCK_NONBLOCK | SOCK_CLOEXEC);

  if( sock == NULL ) {
    if( domain == AF_INET ) {
      if( type == SOCK_STREAM && (protocol == 0 || protocol == IPPROTO_TCP)) {
        rc = zfss_create_tcp(&sock);
        if( rc < 0 )
          return rc;
      }
      else if( type == SOCK_DGRAM && (protocol == 0 || protocol == IPPROTO_UDP)) {
        rc = zfss_create_udp(&sock);
        if( rc < 0 )
          return rc;
      }
    }
  }

  /* If we don't shim this type of socket, just return without bringing up any
   * ZF state. */
  if( sock != NULL ) {
    if( *sock_out == NULL ) {
      /* We've created a new socket: set laddr and raddr */
      /* Default to the implicit-bind host:port until we're told otherwise. */
      zfss_set_laddr(sock, &laddr_implict);
      sock->raddr.sin_family = AF_INET;
      sock->raddr.sin_addr.s_addr = INADDR_ANY;
      sock->raddr.sin_port = 0; /*htons(0)*/
    }
    sock->waitable = NULL;
    sock->flags = nonblock ? ZFSS_FLAG_NONBLOCK : 0;
    sock->file.close = zfss_sock_close;
    zfss_fd_table_insert(fd, &sock->file);
  }

  *sock_out = sock;
  return fd;
}


ZF_INTERCEPT(int, close, int fd)
{
  int saved_errno = errno;

  zfss_file* file = zfss_fd_table_get(fd);
  if( file == NULL || ! zfss_enter_lib() ) {
    errno = saved_errno;
    return zfss_sys_close(fd);
  }

  zfss_stack_poll_if_behind(stack);

  zf_log_ss_info(stack, "::%s(%d)\n", __func__, fd);
  int rc = file->close(file);
  if( rc == 0 )
    rc = zfss_close(file->fd);
  else
    zfss_close(file->fd);
  zfss_exit_lib();
  zf_log_ss_info(stack, "::%s(%d) -> %d\n", __func__, fd, rc);
  if( rc < 0 )
    RET_WITH_ERRNO(-rc);
  return rc;
}


static void __attribute__((constructor))
zfss_sys_iofctl_constructor(void)
{
  zfss_sys_ioctl = (decltype(zfss_sys_ioctl)) dlsym(RTLD_NEXT, "ioctl");
  ZF_TEST(zfss_sys_ioctl);
  zfss_sys_fcntl = (decltype(zfss_sys_fcntl)) dlsym(RTLD_NEXT, "fcntl");
  ZF_TEST(zfss_sys_fcntl);
}

extern "C" __attribute__((visibility("default"))) int
ioctl(int fd, unsigned long request, ...)
{
  struct zfss_socket* sock;
  int saved_errno = errno;
  int rc = -ENOSYS;

  va_list ap;
  va_start(ap, request);
  void* arg = va_arg(ap, void*);
  va_end(ap);

  if( (sock = zfss_fd_table_get_sock(fd)) != NULL && zfss_enter_lib() ) {
    zf_log_ss_info(stack, "::%s(%d, %lu)\n", __func__, fd, request);
    rc = zfss_ioctl(sock, request, arg);
    zfss_exit_lib();
    zf_log_ss_info(stack, "::%s(%d, %lu) -> %d\n", __func__, fd,
                    request, rc);
    if( rc == -ENOTTY )
      rc = -ENOSYS; /* allow ioctl directly on the sys fd */
  }
  if( rc == -ENOSYS )
    return zfss_sys_ioctl(fd, request, arg);
  else if( rc < 0 )
    RET_WITH_ERRNO(-rc);

  errno = saved_errno;
  return rc;
}

extern "C" __attribute__((visibility("default"))) int
fcntl(int fd, int cmd, ...)
{
  struct zfss_socket* sock;
  int saved_errno = errno;
  int rc;

  va_list ap;
  va_start(ap, cmd);
  long arg = va_arg(ap, long);
  va_end(ap);

  rc = zfss_sys_fcntl(fd, cmd, arg);
  if( rc != 0 )
    return rc;

  if( cmd == F_SETFL &&
      (sock = zfss_fd_table_get_sock(fd)) != NULL &&
      zfss_enter_lib() ) {
    zf_log_ss_info(stack, "::%s(%d, %d)\n", __func__, fd, cmd);
    zfss_set_nonblock(sock, arg & O_NONBLOCK);
    zfss_exit_lib();
    zf_log_ss_info(stack, "::%s(%d, %d) -> 0\n", __func__, fd, cmd);
  }

  errno = saved_errno;
  return 0;
}


/* If there's already a pending alarm, how much time is left on it?  The
 * minimum time that we report in such cases is one second, even though the
 * delta between now and the nominal expiry time might be less than this. */
static inline unsigned pending_alarm_time(void)
{
  if( ! process_context.alarm_primed )
    return 0;

  int64_t frc_delta = (int64_t) (process_context.alarm_expiry_time -
                                 zf_frc64());
  uint64_t frc_one_ms = zf_timekeeping_ms2frc(&stack->times.time, 1000);
  return MAX(1u, (unsigned) ((frc_delta + frc_one_ms - 1) / frc_one_ms));
}


/* Intercept alarm().  This is motivated by netperf, which relies (racily!) on
 * SIGALRM interrupting a blocking recv().  A fully sockets-compatible solution
 * that did not fall foul of netperf's race would require something equivalent
 * to Onload's trampolining, which is overkill for the ZF shim.  Instead, we
 * make do with handling alarms only, and not arbitrary signals.  We do this by
 * remembering when the alarm is due and checking for expiry while blocking.
 * To avoid races between our calculated expiry time and the actual delivery of
 * the signal, we synthesise the signal ourselves.  This means that the signal
 * will never be delivered if no-one calls into the shim. */
ZF_INTERCEPT(unsigned, alarm, unsigned seconds)
{
  unsigned remaining_time = pending_alarm_time();

  if( seconds == 0 ) {
    process_context.alarm_primed = false;
  }
  else {
    process_context.alarm_primed = true;

    /* Remember when this alarm will expire. */
    if( stack != NULL )
      process_context.alarm_expiry_time =
        zf_frc64() + zf_timekeeping_ms2frc(&stack->times.time, seconds * 1000);
  }

  /* We don't call the libc alarm() as we don't want the kernel to generate
   * the signal when the alarm expires. */

  return remaining_time;
}


/* Tests (a <= b) after accounting for carry. */
static inline bool FRC_LE(uint64_t a, uint64_t b)
{
  return b - a <= INT64_MAX;
}

/* Checks whether the alarm has expired during this shimmed call and handles it
 * if so. */
static int zfss_process_alarm(void)
{
  /* The alarm has tripped iff alarm_expiry_time <= now. */
  if( process_context.alarm_primed &&
      FRC_LE(process_context.alarm_expiry_time, zf_frc64()) ) {
    process_context.alarm_primed = false;
    raise(SIGALRM);
    return -EINTR;
  }

  return 0;
}

static void zfss_yield(void)
{
  pthread_mutex_unlock(&zfss_lock);
  sched_yield();
  pthread_mutex_lock(&zfss_lock);
}

/* Polls the stack until something happens on it.  Also checks for an interrupt
 * from an alarm. */
int zfss_block_on_stack(void)
{
  auto events = zfss_poll_events;

  while( events == zfss_poll_events ) {
    zfss_stack_poll();
    int rc = zfss_process_alarm();
    if( rc < 0 )
      return rc;
    zfss_yield();
    if( ! zfss_init() )
      return -ENOSYS;
  }

  return 0;
}

/* Intercept nanosleep().  This is motivated by packetdrill, which
 * relays on usleep during longer pauses... and the stack
 * needs to be polled in the meantime */
ZF_INTERCEPT(int, nanosleep, const struct timespec *req, struct timespec *rem)
{
  int saved_errno = errno;

  /* Initialise the library if we haven't done so already */
  if( ! zfss_init_real() || ! zfss_enter_lib() )
    return zfss_sys_nanosleep(req, rem);

  auto now = zf_frc64();
  auto end =
    now +
    zf_timekeeping_ns2frc(&stack->times.time,
                          req->tv_sec * 1000000000ll + req->tv_nsec);
  /* stop yielding this early - for precision */
  auto end_less = end - zf_timekeeping_ms2frc(&stack->times.time, 1);
  while( now < end && zfss_init() ) {
    zfss_stack_poll();
    if( now < end_less )
      zfss_yield();
    now = zf_frc64();
  }
  errno = saved_errno;
  zfss_exit_lib();
  if( zfss_init() )
    zf_log_ss_info(stack, "::%s(%ld%lld)\n", __func__, req->tv_sec, req->tv_nsec);

  if( rem ) {
    rem->tv_sec = 0;
    rem->tv_nsec = 0;
  }

  return 0;
}

ZF_INTERCEPT(int, usleep, useconds_t usec)
{
  timespec d {usec / 1000000, (usec % 1000000) * 1000};
  return nanosleep(&d, NULL);
}
