/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_UTILS_H__
#define __ZF_UTILS_H__


#include <zf_internal/platform.h>
#include <zf_internal/zf_log.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


struct zf_stack;
struct zf_pool;

/* validate statement under sizeof to avoid generating any code,
 * this will check syntax and sort out variable references */
#define zf_validate_statement(statement) static_assert( \
    sizeof(({statement; 1;})) >= 0, "Expression valid")

#define __zf_fail()                                                         \
  do {                                                                      \
    zf_log(NULL, "FAIL at %s:%d\n", __FILE__, __LINE__);                    \
    zf_backtrace();                                                         \
    fflush(stdout);                                                         \
    abort();                                                                \
  } while(0)

#define __zf_assert(exp, file, line)                             \
  do {                                                          \
    if (__builtin_expect((!(exp)), 0)) {                        \
      zf_log(NULL, "zf_assert(%s)\nfrom %s:%d\n",               \
             #exp, (file), (line));                             \
      __zf_fail();                                              \
    }                                                           \
  } while (0)

#define __zf_assert2(e, x, y, file, line)  do {       \
    if(__builtin_expect((!(e)), 0)) {                \
      zf_log(NULL,                                   \
             "zf_assert(%s) where [%s=%" PRIx64 "] " \
             "and [%s=%" PRIx64 "] at %s:%d\n",      \
             #e, #x, (uint64_t)(uintptr_t)(x),       \
             #y, (uint64_t)(uintptr_t)(y),           \
             __FILE__, __LINE__);                    \
      __zf_fail();                                   \
    }                                                \
  } while (0)

/* Notify compiler about an assumption it can make about the code.
 * Use with caution.
 * No code is expected to be generated.  There is some evidence to contrary
 * (e.g. calls to non-inline/non-pure functions, side effects).  There also might
 * be a matter of reordering the code.
 */
#define __zf_assume(exp,F,L) ({ \
    if( !(exp) ) \
      __builtin_unreachable(); \
  })

#define __zf_assume2(exp, x, y, F, L) ({ \
    zf_validate_statement(__zf_assert2((exp),(x),(y),(F),(L))); \
    __zf_assume((exp),(F),(L)); })


/* Redirect assume and assert depending on build type */
#ifdef NDEBUG

/* Defined this way as ensures that these expressions get validated
 * and symbols otherwise non-referenced are not complained about. */
#define zf_fail(exp) zf_validate_statement(__zf_fail(exp))
#define _zf_assert(exp,F,L) \
    zf_validate_statement(__zf_assert((exp),(F),(L)))
#define _zf_assert2(exp, x, y, F, L) \
    zf_validate_statement(__zf_assert2((exp),(x),(y),(F),(L)))

#define _zf_assume __zf_assume
#define _zf_assume2 __zf_assume2

#else

#define zf_fail __zf_fail
#define _zf_assert __zf_assert
#define _zf_assert2 __zf_assert2

#define _zf_assume __zf_assert
#define _zf_assume2 __zf_assert2

#endif


#define zf_assert(exp) \
        _zf_assert(exp, __FILE__, __LINE__)

#define zf_assert_equal(exp1, exp2) \
        _zf_assert2((exp1)==(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_nequal(exp1, exp2) \
        _zf_assert2((exp1)!=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_le(exp1, exp2) \
        _zf_assert2((exp1)<=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_lt(exp1, exp2) \
        _zf_assert2((exp1)<(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_ge(exp1, exp2) \
        _zf_assert2((exp1)>=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_gt(exp1, exp2) \
        _zf_assert2((exp1)>(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assert_flags(val, flags) \
        _zf_assert2(((val)&(flags))==(flags), val, flags, __FILE__, __LINE__)

#define zf_assert_nflags(val, flags) \
        _zf_assert2(((val)&(flags))==0, val, flags, __FILE__, __LINE__)

#define zf_assert_impl(exp1, exp2) \
        _zf_assert2(!(exp1) || (exp2), exp1, exp2, __FILE__, __LINE__)


#define zf_assume(exp) _zf_assume(exp, __FILE__, __LINE__)

#define zf_assume_equal(exp1, exp2) \
        _zf_assume2((exp1)==(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assume_nequal(exp1, exp2) \
        _zf_assume2((exp1)!=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assume_le(exp1, exp2) \
        _zf_assume2((exp1)<=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assume_lt(exp1, exp2) \
        _zf_assume2((exp1)<(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assume_ge(exp1, exp2) \
        _zf_assume2((exp1)>=(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assume_gt(exp1, exp2) \
        _zf_assume2((exp1)>(exp2), exp1, exp2, __FILE__, __LINE__)

#define zf_assume_flags(val, flags) \
        _zf_assume2(((val)&(flags))==(flags), val, flags, __FILE__, __LINE__)

#define zf_assume_nflags(val, flags) \
        _zf_assume2(((val)&(flags))==0, val, flags, __FILE__, __LINE__)

#define zf_assume_impl(exp1, exp2) \
        _zf_assume2(!(exp1) || (exp2), exp1, exp2, __FILE__, __LINE__)



#define ZF_TRY(x)                                                       \
  do {                                                                  \
    int __rc = (x);                                                     \
    auto __report = [&]() ZF_COLD ZF_NOINLINE {                         \
      fprintf(stderr, "ERROR: %s: ZF_TRY(%s) failed\n", __func__, #x);  \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      fflush(stdout);                                                   \
      abort();                                                          \
    };                                                                  \
    if(ZF_UNLIKELY( __rc < 0 )) {                                       \
      __report();                                                       \
    }                                                                   \
  } while( 0 )


#define ZF_TEST(x)                                                      \
  do {                                                                  \
    auto __report = [&]() ZF_COLD ZF_NOINLINE {                         \
      fprintf(stderr, "ERROR: %s: ZF_TEST(%s) failed\n", __func__, #x); \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fflush(stdout);                                                   \
      abort();                                                          \
    };                                                                  \
    if(ZF_UNLIKELY( ! (x) )) {                                          \
      __report();                                                       \
    }                                                                   \
  } while( 0 )


#define ROUND_UP(p, align)   (((p)+(align)-1u) & ~((typeof(p))(align)-1u))

#define MIN(a,b) ({ auto _a = (a); auto _b = (b); \
                   _a < _b ? _a : _b; })
#define MAX(a,b) ({ auto _a = (a); auto _b = (b); \
                   _a < _b ? _b : _a; })

#define ZF_IS_POW2(x)  ((x) && ! ((x) & ((x) - 1)))

/**
 * \brief Calculate memory offset of a field within a struct
 * \param c_type     The struct type.
 * \param mbr_name   The field name to calculate the offset of.
 */
#define ZF_MEMBER_OFFSET(c_type, mbr_name)              \
  ((uint32_t) (uintptr_t)(&((c_type*)0)->mbr_name))

/**
 * \brief Calculate the size of a field within a struct
 * \param c_type     The struct type.
 * \param mbr_name   The field to calculate the size of.
 */
#define ZF_MEMBER_SIZE(c_type, mbr_name)        \
  (sizeof(((c_type*)0)->mbr_name))

#define ZF_CONTAINER(c_type, mbr_name, p_mbr)  \
  ( (c_type*) ((char*)(p_mbr) - ZF_MEMBER_OFFSET(c_type, mbr_name)) )


static inline void*
zf_cache_aligned_alloc(size_t len)
{
  void* ptr;
  int rc = posix_memalign(&ptr, ZF_CACHE_LINE_SIZE, len);
  return rc == 0 ? ptr : NULL;
}

#define _ZF_STRINGIFY(x) #x
#define ZF_STRINGIFY(x)  _ZF_STRINGIFY(x)


#define ZF_ONCE(code) ({ \
    __attribute__((unused)) static const auto once = ({ \
        code; \
      1; }); })

/* XXX: For now, pull in Onload's list implementations. */
extern "C" {
#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>
#include <ci/tools/config.h>
#include <ci/tools/sllist.h>
#include <ci/tools/dllist.h>
}

#include <sys/uio.h>

/* memcpy from a flat buffer to iov */
static inline int
zf_memcpy_flat2iov(struct iovec** p_iov, size_t* p_iovcnt,
                   void* buf, size_t buflen, bool update_iov)
{
  struct iovec* iov = *p_iov;
  size_t iovcnt = *p_iovcnt;
  int copied = 0;

  if( iovcnt == 0 )
    return copied;

  while( buflen > 0 ) {
    size_t size = MIN(iov->iov_len, buflen);
    memcpy(iov->iov_base, buf, size);
    copied += size;

    /* Do we still have more to copy? */
    if( size == buflen || iovcnt == 1) {
      if( update_iov ) {
        if( size < iov->iov_len ) {
          iov->iov_base = (void*)((uintptr_t)iov->iov_base + size);
          iov->iov_len -= size;
        }
        else {
          iov++;
          --iovcnt;
        }
      }
      break;
    }

    /* move the iov and buffer pointer */
    iov++;
    --iovcnt;
    buflen -= size;
    buf = (char*)buf + size;
  }

  if( update_iov ) {
    *p_iov = iov;
    *p_iovcnt = iovcnt;
  }
  return copied;
}


#define ZF_INET_NTOP_DECLARE_BUF(buf_)  \
  char buf_[INET_ADDRSTRLEN]

#define ZF_INET_NTOP_CALL(addr_, buf_)      \
  inet_ntop(AF_INET, &addr_, buf_, INET_ADDRSTRLEN)


static inline constexpr uint16_t zf_htons(uint16_t c)
{
  return (c << 8 | c >> 8);
}

static inline uint16_t zf_ntohs(uint16_t c)
{
  return (c << 8 | c >> 8);
}

#define ZF_CHECK_SOCKADDR_IN(sa, sa_len)        \
  do {                                          \
    if( (sa) == NULL )                          \
      return -EFAULT;                           \
    if( (sa_len) < sizeof(struct sockaddr_in) ) \
      return -EINVAL;                           \
    if( (sa)->sa_family != AF_INET )            \
      return -EAFNOSUPPORT;                     \
  } while (0)


/* Do not allow preloaded libraries (such as Onload) to spoil our notion of
 * socket. */
#include <ci/internal/syscall.h>
static inline int zf_sys_socket(int domain, int type, int protocol)
{
  return my_syscall3(socket, domain, type, protocol);
}


static inline int
zf_timespec_compare(struct timespec *lhs, struct timespec *rhs)
{
  if( lhs->tv_sec < rhs->tv_sec )
    return -1;
  if( lhs->tv_sec > rhs->tv_sec )
    return 1;
  return lhs->tv_nsec - rhs->tv_nsec;
}


#endif /* __ZF_UTILS_H__ */
