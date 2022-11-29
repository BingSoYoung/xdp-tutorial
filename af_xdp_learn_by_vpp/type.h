#ifndef _type_h
#define _type_h

typedef unsigned int u32;
typedef unsigned char u8;

#define clib_max(a, b) ((a)>(b)?(a):(b))

#define __clib_unused __attribute__ ((unused))
#define __clib_weak __attribute__ ((weak))
#define __clib_packed __attribute__ ((packed))
#define __clib_flatten	   __attribute__ ((flatten))
#define __clib_constructor __attribute__ ((constructor))
#define __clib_noinline __attribute__ ((noinline))

/* Default cache line size of 64 bytes. */
#ifndef CLIB_LOG2_CACHE_LINE_BYTES
#define CLIB_LOG2_CACHE_LINE_BYTES 6
#endif

/* How much data prefetch instruction prefetches */
#ifndef CLIB_LOG2_CACHE_PREFETCH_BYTES
#define CLIB_LOG2_CACHE_PREFETCH_BYTES CLIB_LOG2_CACHE_LINE_BYTES
#endif

/* Default cache line fill buffers. */
#ifndef CLIB_N_PREFETCHES
#define CLIB_N_PREFETCHES 16
#endif

#define CLIB_CACHE_LINE_BYTES	  (1 << CLIB_LOG2_CACHE_LINE_BYTES)
#define CLIB_CACHE_PREFETCH_BYTES (1 << CLIB_LOG2_CACHE_PREFETCH_BYTES)
#define CLIB_CACHE_LINE_ALIGN_MARK(mark)                                      \
  u8 mark[0] __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)))
#define CLIB_CACHE_LINE_ROUND(x)                                              \
  ((x + CLIB_CACHE_LINE_BYTES - 1) & ~(CLIB_CACHE_LINE_BYTES - 1))

/* Read/write arguments to __builtin_prefetch. */
#define CLIB_PREFETCH_READ 0
#define CLIB_PREFETCH_LOAD 0	/* alias for read */
#define CLIB_PREFETCH_WRITE 1
#define CLIB_PREFETCH_STORE 1	/* alias for write */

#define _CLIB_PREFETCH(n, size, type)                                         \
  if ((size) > (n) *CLIB_CACHE_PREFETCH_BYTES)                                \
    __builtin_prefetch (_addr + (n) *CLIB_CACHE_PREFETCH_BYTES,               \
			CLIB_PREFETCH_##type, /* locality */ 3);


u32
is_pow2 (u32 x)
{
  return 0 == (x & (x - 1));
}

#endif