/* -*- linux-c -*-
 * Copyright (C) 2005-2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_STRING_H_
#define _STP_STRING_H_

#define to_oct_digit(c) ((c) + '0')
#define to_hex_digit(c) ({ char __c = (c); __c += (__c < 10 ? '0' : 'A' - 10); __c; })

static int _stp_text_str(char *out, const char *in, int inlen, int outlen, int quoted, int user);


#if defined(__KERNEL__)
/*
 * Powerpc uses a paranoid user address check in __get_user() which
 * spews warnings "BUG: Sleeping function...." when DEBUG_SPINLOCK_SLEEP
 * is enabled. With 2.6.21 and above, a newer variant __get_user_inatomic
 * is provided without the paranoid check. Use it if available, fall back
 * to __get_user() if not. Other archs can use __get_user() as is
 */
#if defined(__powerpc__) && defined(__get_user_inatomic)
#define __stp_get_user(x, ptr) __get_user_inatomic (x, ptr)
#else
#define __stp_get_user(x, ptr) __get_user (x, ptr)
#endif

#elif defined(__DYNINST__)

#define __stp_get_user(x, ptr) __get_user(x, ptr)

#endif


/** Safely read from userspace or kernelspace.
 * On success, returns 0. Returns -EFAULT on error.
 *
 * This uses __get_user() to read from userspace or
 * kernelspace.  Will not sleep or cause pagefaults when
 * called from within a kprobe context.
 *
 * @param segment . KERNEL_DS for kernel access
 *                  USER_DS for userspace.
 */

/* XXX: duplicates _stp_deref() in loc2c-runtime.h */
/* NB: lookup_bad_addr cannot easily be called from here due to header
 * file ordering. */
/* XXX: no error signalling */
#define _stp_read_address(x, ptr, segment)    \
	({				      \
		long ret;		      \
		mm_segment_t ofs = get_fs();  \
		set_fs(segment);	      \
                pagefault_disable();          \
                if (!access_ok(VERIFY_READ, (char __user *)ptr, sizeof(x))) \
                     ret = -EFAULT;           \
                else                          \
                     ret = __stp_get_user(x, ptr);                          \
                pagefault_enable();           \
		set_fs(ofs);		      \
		ret;   			      \
	})




#endif /* _STP_STRING_H_ */
