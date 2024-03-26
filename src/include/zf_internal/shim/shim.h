/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF - internal declarations
 */

#ifndef __ZF_INTERNAL_SHIM_H__
#define __ZF_INTERNAL_SHIM_H__

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#define ONLOAD_INCLUDE_DS_DATA_ONLY
#include <onload/extensions.h>
#undef ONLOAD_INCLUDE_DS_DATA_ONLY

/* This should be the only internal header that we include: we maintain a
 * policy of using the public API only, but there are some handy generic macros
 * in here. */
#include <zf_internal/utils.h>
#include <zf_internal/shim/waitable_ext.h>

static const zf_logger zf_log_ss_err(ZF_LC_SOCKET_SHIM, ZF_LL_ERR);
static const zf_logger zf_log_ss_info(ZF_LC_SOCKET_SHIM, ZF_LL_INFO);
#ifndef NDEBUG
static const zf_logger zf_log_ss_trace(ZF_LC_SOCKET_SHIM, ZF_LL_TRACE);
#else
#define zf_log_ss_trace(...) do{}while(0)
#endif

/*********** Generic File Descriptor handlers ***********/

struct zfss_file {
  /* file descriptor of the OS socket or OS epoll set */
  int fd;

  /* We can use this "close" handler as "fd type": epoll or socket.
   * Currently, we assume that it is socket if it is used a socket and it
   * is epoll if it is used as epoll. */
  int (*close)(struct zfss_file*);
};
bool zfss_enter_lib(void);
void zfss_exit_lib(void);
int zfss_fd_table_insert(int fd, struct zfss_file* file);
struct zfss_file* zfss_fd_table_get(int fd);
struct zfss_socket* zfss_fd_table_get_sock(int fd);
int zfss_close(int fd);
int zfss_handover(int fd);
bool zfss_init(void);
bool zfss_init_real(void);


/*********** Interception handlers ***********/

#include <dlfcn.h>

template< class T > struct remove_noexcept { typedef T type; };

template<typename Ret, typename... Args>
struct remove_noexcept<Ret(*)(Args...) noexcept> { typedef Ret (*type)(Args...); };

/* Records address of the real function X in zfss_sys_X. */
#define ZF_FIND_REAL_API_ENTRY(func) \
  remove_noexcept< decltype(&::func) >::type zfss_sys_##func;                 \
  static void __attribute__((constructor))                                    \
  zfss_sys_##func##_constructor(void)                                         \
  {                                                                           \
    zfss_sys_##func = (decltype(zfss_sys_##func)) dlsym(RTLD_NEXT, #func);    \
    ZF_TEST(zfss_sys_##func);                                                 \
  }

#define ZF_INTERCEPT(ret, func, ...) \
  ZF_FIND_REAL_API_ENTRY(func) \
  extern "C" __attribute__((visibility("default"))) ret func (__VA_ARGS__)

#define RET_WITH_ERRNO(e) do{ errno = e; return -1; } while(0);


#define ZF_DECLARE_REAL_API_ENTRY(func) \
  extern remove_noexcept< decltype(&::func) >::type zfss_sys_##func
ZF_DECLARE_REAL_API_ENTRY(bind);
ZF_DECLARE_REAL_API_ENTRY(recvmsg);
ZF_DECLARE_REAL_API_ENTRY(sendmsg);
ZF_DECLARE_REAL_API_ENTRY(close);
ZF_DECLARE_REAL_API_ENTRY(getsockopt);


/************ Socket-specific data and functions ***********/

/* RHEL6 doesn't have sendmmsg(), so let's just forget about it for now. */
#define SHIM_SENDMMSG 0

/* Set of MSG_* flags we do support.
 * MSG_MORE is a bit special: it is supported by TCP send only. */
#define SHIM_MSG_FLAGS (MSG_DONTWAIT | MSG_WAITALL)

/* Waitable and events it is able to report */
struct zfss_waitable {
  struct zf_waitable* w;
  uint32_t ev;
};
/* Each socket has no more than 3 waitables to wait on. */
#define SHIM_SOCK_WAITABLES_MAX 3


template <typename APICall, APICall f>
struct ShimFDType;

template <typename Ret, typename... Args, Ret (*api_call)(int fd, Args...)>
struct ShimFDType<Ret(*)(int fd, Args...), api_call>
{
    typedef Ret (*Type)(struct zfss_socket*, Args...);
};

#define ZF_SOCKET_OP(func) \
  ShimFDType<remove_noexcept< decltype(&::func) >::type, &::func>::Type func
struct zfss_socket_ops {
  ZF_SOCKET_OP(close);
  ZF_SOCKET_OP(bind);
  ZF_SOCKET_OP(connect);
  ZF_SOCKET_OP(listen);
  ZF_SOCKET_OP(accept4);
  ZF_SOCKET_OP(accept);
  ZF_SOCKET_OP(shutdown);
  ZF_SOCKET_OP(getsockname);
  ZF_SOCKET_OP(getpeername);
  ZF_SOCKET_OP(getsockopt);
  ZF_SOCKET_OP(setsockopt);

  ZF_SOCKET_OP(recvmmsg);
  ZF_SOCKET_OP(recvmsg);
  ZF_SOCKET_OP(recvfrom);
  ZF_SOCKET_OP(recv);
  ZF_SOCKET_OP(read);
  ZF_SOCKET_OP(readv);

#if SHIM_SENDMMSG
  ZF_SOCKET_OP(sendmmsg);
#endif
  ZF_SOCKET_OP(sendmsg);
  ZF_SOCKET_OP(sendto);
  ZF_SOCKET_OP(send);
  ZF_SOCKET_OP(write);
  ZF_SOCKET_OP(writev);

  uint32_t (*events)(struct zfss_socket*);
  int (*waitables)(struct zfss_socket*, struct zfss_waitable*);
};


typedef uint8_t zfss_flag;
static const zfss_flag ZFSS_FLAG_SHUT_READ  = 0x1;
static const zfss_flag ZFSS_FLAG_SHUT_WRITE = 0x2;
static const zfss_flag ZFSS_FLAG_NONBLOCK   = 0x4;
static const zfss_flag ZFSS_FLAG_BOUND      = 0x8;

struct zfss_socket {
  /* Common per-file structure */
  zfss_file file;

  /* Handlers for intercepted socket functions */
  const struct zfss_socket_ops* ops;

  /* Local and remote addresses of the connection */
  struct sockaddr_in laddr;
  struct sockaddr_in raddr;

  zfss_flag flags;

  /* Per-socket waitable to flag SHUT_RW and similar things */
  zf_waitable* waitable;
};


/* Per-shim variables initialised at in library init. */
extern struct zf_stack* stack;
extern struct zf_attr* attr;
extern struct zf_attr* attr_short_poll;
extern struct sockaddr_in laddr_implict;

int zfss_create(int domain, int type, int protocol,
                struct zfss_socket** sock_out);
int zfss_create_udp(struct zfss_socket** sock_out);
int zfss_create_tcp(struct zfss_socket** sock_out);


/* Common helpers to handle recvfrom() via recvmmsg(), etc. */
void
zfss_set_laddr(struct zfss_socket* sock, const struct sockaddr_in* addr);
int
zfss_bind(struct zfss_socket* sock, const struct sockaddr* addr,
          socklen_t addrlen);
int
zfss_set_raddr(struct zfss_socket* sock, const struct sockaddr* addr,
               socklen_t addrlen);
uint32_t
zfss_events(struct zfss_socket* sock);
int
zfss_shutdown(struct zfss_socket* sock, int how);
void
zfss_set_nonblock(struct zfss_socket* sock, bool set);
int
zfss_ioctl(struct zfss_socket* sock, unsigned long request, void* arg);
int
zfss_getsockopt(struct zfss_socket* sock, int level, int optname,
                void *optval, socklen_t *optlen);

ssize_t
zfss_recvfrom(struct zfss_socket* sock, void* buf, size_t len, int flags,
              struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t
zfss_recv(struct zfss_socket* sock, void* buf, size_t len, int flags);

ssize_t
zfss_read(struct zfss_socket* sock, void* buf, size_t count);
ssize_t
zfss_readv(struct zfss_socket* sock, const struct iovec* iov, int iovcnt);

#include <tuple>
template <unsigned i, typename T>
struct argtype {};

template <unsigned i, typename R, typename... Args>
struct argtype<i, R (*)(Args...)> {
  typedef typename std::tuple_element<i, std::tuple<Args...> >::type type;
};

/* Work around the different signatures of recvmsg()
 * in different versions of glibc. */
typedef typename argtype<4,decltype(&recvmmsg)>::type recvmsg_timeout_t;
int
zfss_recvmmsg(struct zfss_socket* sock, struct mmsghdr *msgvec,
              unsigned int vlen, int flags, recvmsg_timeout_t timeout);

#if SHIM_SENDMMSG
int
zfss_sendmmsg(struct zfss_socket* sock, struct mmsghdr *msgvec,
              unsigned int vlen, int flags);
#endif
ssize_t
zfss_sendto(struct zfss_socket* sock, const void* buf, size_t len,
            int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t
zfss_send(struct zfss_socket* sock, const void* buf, size_t len,
          int flags);
ssize_t
zfss_write(struct zfss_socket* sock, const void* buf, size_t len);
ssize_t
zfss_writev(struct zfss_socket* sock, const struct iovec* iov, int iovcnt);

int
zfss_getsockname(struct zfss_socket* sock, struct sockaddr *addr,
                 socklen_t *addrlen);
int
zfss_getpeername(struct zfss_socket* sock, struct sockaddr *addr,
                 socklen_t *addrlen);

int
zfss_no_listen(struct zfss_socket* sock, int backlog);
int
zfss_no_accept4(struct zfss_socket* sock,
                struct sockaddr *addr, socklen_t *addrlen, int flags);
int
zfss_accept(struct zfss_socket* sock,
            struct sockaddr *addr, socklen_t *addrlen);

struct zf_waitable* zfss_sock_waitable(struct zfss_socket* sock);

extern int zfss_stack_poll(void);

extern int zfss_block_on_stack(void);

/* Delegated send API */
ZF_LIBENTRY enum onload_delegated_send_rc
onload_delegated_send_prepare(int fd, int size, unsigned flags,
                              struct onload_delegated_send* out);

ZF_LIBENTRY void
onload_delegated_send_tcp_update(struct onload_delegated_send* ds, int bytes,
                                 int push);

ZF_LIBENTRY void
onload_delegated_send_tcp_advance(struct onload_delegated_send* ds, int bytes);

ZF_LIBENTRY int
onload_delegated_send_cancel(int fd);

ZF_LIBENTRY int
onload_delegated_send_complete(int fd, const struct iovec* iov,
                               int iovlen, int flags);

#endif /* __ZF_INTERNAL_SHIM_H__ */
