/* -*- linux-c -*- */
/* Math functions
 * Copyright (C) 2005 Red Hat Inc.
 * Portions (C) Free Software Foundation, Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAPLINUX_ARITH_C_ 
#define _STAPLINUX_ARITH_C_

/** @file arith.
 * @brief Implements various arithmetic-related helper functions
 */


/* 64-bit division for 64-bit cpus and i386 */
/* Other 32-bit cpus will need to modify this file. */

#if defined (__i386__) || defined(__arm__) || \
	(defined(__powerpc__) && !defined(__powerpc64__))
static long long _div64 (long long u, long long v);
static long long _mod64 (long long u, long long v);
#endif

/* 31 bit s390 suupport is not yet included, it may never be.
#ifdef __s390__
static long long _div64 (long long u, long long v);
static long long _mod64 (long long u, long long v);
#endif
*/

/** Divide x by y.  In case of division-by-zero,
 * set context error string, and return 0
 */
static int64_t _stp_div64 (const char **error, int64_t x, int64_t y)
{
	// check for division-by-zero
	if (unlikely (y == 0)) {
		if (error) *error = "division by 0";
		return 0;
	}

	if (unlikely (y == -1))
		return -x;

#if defined (__LP64__)
	return x/y;
#else
	if (likely ((x >= LONG_MIN && x <= LONG_MAX) &&
		    (y >= LONG_MIN && y <= LONG_MAX))) {
		return (long)x / (long)y;
	} else
		return _div64 (x, y);
#endif
}


/** Modulo x by y.  In case of division-by-zero,
 * set context error string, and return any 0
 */
static int64_t _stp_mod64 (const char **error, int64_t x, int64_t y)
{
	// check for division-by-zero
	if (unlikely (y == 0)) {
		if (error) *error = "division by 0";
		return 0;
	}
	
	if (unlikely (y == 1 || y == -1))
		return 0;
	
#if defined (__LP64__)
	return x%y;
#else
	if (likely ((x >= LONG_MIN && x <= LONG_MAX) &&
		    (y >= LONG_MIN && y <= LONG_MAX))) {
		return (long)x % (long)y;
	} else
		return _mod64 (x, y);
#endif
}


/** Return a random integer between 0 and n - 1.
 * @param n how far from zero to go.  Make it positive but less than a million or so.
 */
static unsigned long _stp_random_u (unsigned long n)
{
	static unsigned long seed;
	static int initialized_p = 0;

	if (unlikely (! initialized_p)) {
		seed = (unsigned long) jiffies;
		initialized_p = 1;
	}

	/* from glibc rand man page */
	seed = seed * 1103515245 + 12345;

	return (n == 0 ? 0 : seed % n);
}


/** Return a random integer between -n and n.
 * @param n how far from zero to go.  Make it positive but less than a million or so.
 */
static int _stp_random_pm (unsigned n)
{
        return -(int)n + (int)_stp_random_u (2*n + 1);
}



#if defined (__i386__) || defined (__arm__) || \
	(defined(__powerpc__) && !defined(__powerpc64__))

/* 64-bit division functions extracted from libgcc */
typedef long long DWtype;
typedef unsigned long long UDWtype;
typedef unsigned long UWtype;
typedef long Wtype;
typedef unsigned int USItype;
typedef unsigned int UQItype	__attribute__ ((mode (QI)));

#ifdef _BIG_ENDIAN
struct DWstruct {Wtype high, low;};
#else
struct DWstruct {Wtype low, high;};
#endif

#define __CLOBBER_CC : "cc"

#define W_TYPE_SIZE 32

#define __BITS4 (W_TYPE_SIZE / 4)
#define __ll_B ((UWtype) 1 << (W_TYPE_SIZE / 2))
#define __ll_lowpart(t) ((UWtype) (t) & (__ll_B - 1))
#define __ll_highpart(t) ((UWtype) (t) >> (W_TYPE_SIZE / 2))

typedef union
{
	struct DWstruct s;
	DWtype ll;
} DWunion;


#if defined (__i386__)
/* these are the i386 versions of these macros from gcc/longlong.h */

#define umul_ppmm(w1, w0, u, v)			\
	__asm__ ("mull %3"			\
		 : "=a" ((USItype) (w0)),	\
		   "=d" ((USItype) (w1))	\
		 : "%0" ((USItype) (u)),	\
		   "rm" ((USItype) (v)))

#define sub_ddmmss(sh, sl, ah, al, bh, bl)	\
	__asm__ ("subl %5,%1\n\tsbbl %3,%0"	\
		 : "=r" ((USItype) (sh)),	\
		   "=&r" ((USItype) (sl))	\
		 : "0" ((USItype) (ah)),	\
		   "g" ((USItype) (bh)),	\
		   "1" ((USItype) (al)),	\
		   "g" ((USItype) (bl)))

#define udiv_qrnnd(q, r, n1, n0, dv)		\
	__asm__ ("divl %4"			\
		 : "=a" ((USItype) (q)),	\
		   "=d" ((USItype) (r))		\
		 : "0" ((USItype) (n0)),	\
		   "1" ((USItype) (n1)),	\
		   "rm" ((USItype) (dv)))

#define count_leading_zeros(count, x)					\
	do {								\
		USItype __cbtmp;					\
		__asm__ ("bsrl %1,%0"					\
			 : "=r" (__cbtmp) : "rm" ((USItype) (x)));	\
		(count) = __cbtmp ^ 31;					\
	} while (0)

#elif defined (__powerpc__)
/* these are the ppc versions of these macros from gcc/longlong.h */

#define sub_ddmmss(sh, sl, ah, al, bh, bl) \
  do {									\
    if (__builtin_constant_p (ah) && (ah) == 0)				\
      __asm__ ("{sf%I3|subf%I3c} %1,%4,%3\n\t{sfze|subfze} %0,%2"	\
	       : "=r" (sh), "=&r" (sl) : "r" (bh), "rI" (al), "r" (bl));\
    else if (__builtin_constant_p (ah) && (ah) == ~(USItype) 0)		\
      __asm__ ("{sf%I3|subf%I3c} %1,%4,%3\n\t{sfme|subfme} %0,%2"	\
	       : "=r" (sh), "=&r" (sl) : "r" (bh), "rI" (al), "r" (bl));\
    else if (__builtin_constant_p (bh) && (bh) == 0)			\
      __asm__ ("{sf%I3|subf%I3c} %1,%4,%3\n\t{ame|addme} %0,%2"		\
	       : "=r" (sh), "=&r" (sl) : "r" (ah), "rI" (al), "r" (bl));\
    else if (__builtin_constant_p (bh) && (bh) == ~(USItype) 0)		\
      __asm__ ("{sf%I3|subf%I3c} %1,%4,%3\n\t{aze|addze} %0,%2"		\
	       : "=r" (sh), "=&r" (sl) : "r" (ah), "rI" (al), "r" (bl));\
    else								\
      __asm__ ("{sf%I4|subf%I4c} %1,%5,%4\n\t{sfe|subfe} %0,%3,%2"	\
	       : "=r" (sh), "=&r" (sl)					\
	       : "r" (ah), "r" (bh), "rI" (al), "r" (bl));		\
  } while (0)

#define count_leading_zeros(count, x) \
  __asm__ ("{cntlz|cntlzw} %0,%1" : "=r" (count) : "r" (x))
#define COUNT_LEADING_ZEROS_0 32

#define umul_ppmm(ph, pl, m0, m1) \
  do {									\
    USItype __m0 = (m0), __m1 = (m1);					\
    __asm__ ("mulhwu %0,%1,%2" : "=r" (ph) : "%r" (m0), "r" (m1));	\
    (pl) = __m0 * __m1;							\
  } while (0)

#elif defined (__arm__)

#define sub_ddmmss(sh, sl, ah, al, bh, bl) \
  __asm__ ("subs	%1, %4, %5\n\tsbc	%0, %2, %3"		\
	   : "=r" ((USItype) (sh)),					\
	     "=&r" ((USItype) (sl))					\
	   : "r" ((USItype) (ah)),					\
	     "rI" ((USItype) (bh)),					\
	     "r" ((USItype) (al)),					\
	     "rI" ((USItype) (bl)) __CLOBBER_CC)
#define umul_ppmm(xh, xl, a, b) \
{register USItype __t0, __t1, __t2;					\
  __asm__ ("%@ Inlined umul_ppmm\n"					\
	   "	mov	%2, %5, lsr #16\n"				\
	   "	mov	%0, %6, lsr #16\n"				\
	   "	bic	%3, %5, %2, lsl #16\n"				\
	   "	bic	%4, %6, %0, lsl #16\n"				\
	   "	mul	%1, %3, %4\n"					\
	   "	mul	%4, %2, %4\n"					\
	   "	mul	%3, %0, %3\n"					\
	   "	mul	%0, %2, %0\n"					\
	   "	adds	%3, %4, %3\n"					\
	   "	addcs	%0, %0, #65536\n"				\
	   "	adds	%1, %1, %3, lsl #16\n"				\
	   "	adc	%0, %0, %3, lsr #16"				\
	   : "=&r" ((USItype) (xh)),					\
	     "=r" ((USItype) (xl)),					\
	     "=&r" (__t0), "=&r" (__t1), "=r" (__t2)			\
	   : "r" ((USItype) (a)),					\
	     "r" ((USItype) (b)) __CLOBBER_CC );}

#endif

#define __udiv_qrnnd_c(q, r, n1, n0, d) \
  do {									\
    UWtype __d1, __d0, __q1, __q0;					\
    UWtype __r1, __r0, __m;						\
    __d1 = __ll_highpart (d);						\
    __d0 = __ll_lowpart (d);						\
									\
    __r1 = (n1) % __d1;							\
    __q1 = (n1) / __d1;							\
    __m = (UWtype) __q1 * __d0;						\
    __r1 = __r1 * __ll_B | __ll_highpart (n0);				\
    if (__r1 < __m)							\
      {									\
	__q1--, __r1 += (d);						\
	if (__r1 >= (d)) /* i.e. we didn't get carry when adding to __r1 */\
	  if (__r1 < __m)						\
	    __q1--, __r1 += (d);					\
      }									\
    __r1 -= __m;							\
									\
    __r0 = __r1 % __d1;							\
    __q0 = __r1 / __d1;							\
    __m = (UWtype) __q0 * __d0;						\
    __r0 = __r0 * __ll_B | __ll_lowpart (n0);				\
    if (__r0 < __m)							\
      {									\
	__q0--, __r0 += (d);						\
	if (__r0 >= (d))						\
	  if (__r0 < __m)						\
	    __q0--, __r0 += (d);					\
      }									\
    __r0 -= __m;							\
									\
    (q) = (UWtype) __q1 * __ll_B | __q0;				\
    (r) = __r0;								\
  } while (0)

#if !defined (udiv_qrnnd)
#define UDIV_NEEDS_NORMALIZATION 1
#define udiv_qrnnd __udiv_qrnnd_c
#else
#define UDIV_NEEDS_NORMALIZATION 0
#endif

#if !defined (count_leading_zeros)
static const UQItype _stp_clz_tab[256] =
{
  0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
};

#define count_leading_zeros(count, x) \
  do {									\
    UWtype __xr = (x);							\
    UWtype __a;								\
									\
    if (W_TYPE_SIZE <= 32)						\
      {									\
	__a = __xr < ((UWtype)1<<2*__BITS4)				\
	  ? (__xr < ((UWtype)1<<__BITS4) ? 0 : __BITS4)			\
	  : (__xr < ((UWtype)1<<3*__BITS4) ?  2*__BITS4 : 3*__BITS4);	\
      }									\
    else								\
      {									\
	for (__a = W_TYPE_SIZE - 8; __a > 0; __a -= 8)			\
	  if (((__xr >> __a) & 0xff) != 0)				\
	    break;							\
      }									\
									\
    (count) = W_TYPE_SIZE - (_stp_clz_tab[__xr >> __a] + __a);		\
  } while (0)
#define COUNT_LEADING_ZEROS_0 W_TYPE_SIZE
#endif

static UDWtype
_stp_udivmoddi4 (UDWtype n, UDWtype d, UDWtype *rp)
{
  const DWunion nn = {.ll = n};
  const DWunion dd = {.ll = d};
  DWunion ww, rr;
  UWtype d0, d1, n0, n1, n2;
  UWtype q0, q1;
  UWtype b, bm;

  d0 = dd.s.low;
  d1 = dd.s.high;
  n0 = nn.s.low;
  n1 = nn.s.high;

#if !UDIV_NEEDS_NORMALIZATION
  if (d1 == 0)
    {
      if (d0 > n1)
	{
	  /* 0q = nn / 0D */

	  udiv_qrnnd (q0, n0, n1, n0, d0);
	  q1 = 0;

	  /* Remainder in n0.  */
	}
      else
	{
	  /* qq = NN / 0d */

	  if (d0 == 0)
	    d0 = 1 / d0;	/* Divide intentionally by zero.  */

	  udiv_qrnnd (q1, n1, 0, n1, d0);
	  udiv_qrnnd (q0, n0, n1, n0, d0);

	  /* Remainder in n0.  */
	}

      if (rp != 0)
	{
	  rr.s.low = n0;
	  rr.s.high = 0;
	  *rp = rr.ll;
	}
    }

#else /* UDIV_NEEDS_NORMALIZATION */

  if (d1 == 0)
    {
      if (d0 > n1)
	{
	  /* 0q = nn / 0D */

	  count_leading_zeros (bm, d0);

	  if (bm != 0)
	    {
	      /* Normalize, i.e. make the most significant bit of the
		 denominator set.  */

	      d0 = d0 << bm;
	      n1 = (n1 << bm) | (n0 >> (W_TYPE_SIZE - bm));
	      n0 = n0 << bm;
	    }

	  udiv_qrnnd (q0, n0, n1, n0, d0);
	  q1 = 0;

	  /* Remainder in n0 >> bm.  */
	}
      else
	{
	  /* qq = NN / 0d */

	  if (d0 == 0)
	    d0 = 1 / d0;	/* Divide intentionally by zero.  */

	  count_leading_zeros (bm, d0);

	  if (bm == 0)
	    {
	      /* From (n1 >= d0) /\ (the most significant bit of d0 is set),
		 conclude (the most significant bit of n1 is set) /\ (the
		 leading quotient digit q1 = 1).

		 This special case is necessary, not an optimization.
		 (Shifts counts of W_TYPE_SIZE are undefined.)  */

	      n1 -= d0;
	      q1 = 1;
	    }
	  else
	    {
	      /* Normalize.  */

	      b = W_TYPE_SIZE - bm;

	      d0 = d0 << bm;
	      n2 = n1 >> b;
	      n1 = (n1 << bm) | (n0 >> b);
	      n0 = n0 << bm;

	      udiv_qrnnd (q1, n1, n2, n1, d0);
	    }

	  /* n1 != d0...  */

	  udiv_qrnnd (q0, n0, n1, n0, d0);

	  /* Remainder in n0 >> bm.  */
	}

      if (rp != 0)
	{
	  rr.s.low = n0 >> bm;
	  rr.s.high = 0;
	  *rp = rr.ll;
	}
    }
#endif /* UDIV_NEEDS_NORMALIZATION */

  else
    {
      if (d1 > n1)
	{
	  /* 00 = nn / DD */

	  q0 = 0;
	  q1 = 0;

	  /* Remainder in n1n0.  */
	  if (rp != 0)
	    {
	      rr.s.low = n0;
	      rr.s.high = n1;
	      *rp = rr.ll;
	    }
	}
      else
	{
	  /* 0q = NN / dd */

	  count_leading_zeros (bm, d1);
	  if (bm == 0)
	    {
	      /* From (n1 >= d1) /\ (the most significant bit of d1 is set),
		 conclude (the most significant bit of n1 is set) /\ (the
		 quotient digit q0 = 0 or 1).

		 This special case is necessary, not an optimization.  */

	      /* The condition on the next line takes advantage of that
		 n1 >= d1 (true due to program flow).  */
	      if (n1 > d1 || n0 >= d0)
		{
		  q0 = 1;
		  sub_ddmmss (n1, n0, n1, n0, d1, d0);
		}
	      else
		q0 = 0;

	      q1 = 0;

	      if (rp != 0)
		{
		  rr.s.low = n0;
		  rr.s.high = n1;
		  *rp = rr.ll;
		}
	    }
	  else
	    {
	      UWtype m1, m0;
	      /* Normalize.  */

	      b = W_TYPE_SIZE - bm;

	      d1 = (d1 << bm) | (d0 >> b);
	      d0 = d0 << bm;
	      n2 = n1 >> b;
	      n1 = (n1 << bm) | (n0 >> b);
	      n0 = n0 << bm;

	      udiv_qrnnd (q0, n1, n2, n1, d1);
	      umul_ppmm (m1, m0, q0, d0);

	      if (m1 > n1 || (m1 == n1 && m0 > n0))
		{
		  q0--;
		  sub_ddmmss (m1, m0, m1, m0, d1, d0);
		}

	      q1 = 0;

	      /* Remainder in (n1n0 - m1m0) >> bm.  */
	      if (rp != 0)
		{
		  sub_ddmmss (n1, n0, n1, n0, m1, m0);
		  rr.s.low = (n1 << b) | (n0 >> bm);
		  rr.s.high = n1 >> bm;
		  *rp = rr.ll;
		}
	    }
	}
    }

  ww.s.low = q0; ww.s.high = q1;
  return ww.ll;
}

static long long _div64 (long long u, long long v)
{
	long c = 0;
	DWunion uu = {.ll = u};
	DWunion vv = {.ll = v};
	DWtype w;
	
	if (uu.s.high < 0)
		c = ~c,
			uu.ll = -uu.ll;
	if (vv.s.high < 0)
		c = ~c,
			vv.ll = -vv.ll;
	
	w = _stp_udivmoddi4 (uu.ll, vv.ll, (UDWtype *) 0);
	if (c)
		w = -w;
	
	return w;
}

static long long _mod64 (long long u, long long v)
{
	long c = 0;
	DWunion uu = {.ll = u};
	DWunion vv = {.ll = v};
	DWtype w;
	
	if (uu.s.high < 0)
		c = ~c,
			uu.ll = -uu.ll;
	if (vv.s.high < 0)
		vv.ll = -vv.ll;
	
	(void) _stp_udivmoddi4 (uu.ll, vv.ll, (UDWtype*)&w);
	if (c)
		w = -w;
	
	return w;
}

#endif /* __i386__ || __arm__ || (__powerpc__ && !__powerpc64__) */

#endif /* _STAPLINUX_ARITH_C_ */
