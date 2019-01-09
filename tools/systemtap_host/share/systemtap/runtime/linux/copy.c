/* -*- linux-c -*- 
 * Copy from user space functions
 * Copyright (C) 2005-2014 Red Hat Inc.
 * Copyright (C) 2005 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STAPLINUX_COPY_C_		/* -*- linux-c -*- */
#define _STAPLINUX_COPY_C_

/** @file copy.c
 * @brief Functions to copy from user space.
 */

/** @addtogroup copy Functions to copy from user space.
 * Functions to copy from user space.
 * None of these functions will sleep (for example to allow pages
 * to be swapped in). It is possible (although rare) that the data
 * in user space will not present and these functions will return an error.
 * @{
 */

#ifdef CONFIG_GENERIC_STRNCPY_FROM_USER
#define __stp_strncpy_from_user(dst,src,count,res) \
	do { res = strncpy_from_user(dst, src, count); } while(0)
#else  /* !CONFIG_GENERIC_STRNCPY_FROM_USER */
#if defined (__i386__)
#define __stp_strncpy_from_user(dst,src,count,res)			   \
do {									   \
	int __d0, __d1, __d2;						   \
	__asm__ __volatile__(						   \
		"	testl %1,%1\n"					   \
		"	jz 2f\n"					   \
		"0:	lodsb\n"					   \
		"	stosb\n"					   \
		"	testb %%al,%%al\n"				   \
		"	jz 1f\n"					   \
		"	decl %1\n"					   \
		"	jnz 0b\n"					   \
		"1:	subl %1,%0\n"					   \
		"2:\n"							   \
		".section .fixup,\"ax\"\n"				   \
		"3:	movl %5,%0\n"					   \
		"	jmp 2b\n"					   \
		".previous\n"						   \
		".section __ex_table,\"a\"\n"				   \
		"	.align 4\n"					   \
		"	.long 0b,3b\n"					   \
		".previous"						   \
		: "=d"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1),	   \
		  "=&D" (__d2)						   \
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst) \
		: "memory");						   \
} while (0)
#elif defined (__x86_64__)
#define __stp_strncpy_from_user(dst,src,count,res)			   \
do {									   \
	long __d0, __d1, __d2;						   \
	__asm__ __volatile__(						   \
		"	testq %1,%1\n"					   \
		"	jz 2f\n"					   \
		"0:	lodsb\n"					   \
		"	stosb\n"					   \
		"	testb %%al,%%al\n"				   \
		"	jz 1f\n"					   \
		"	decq %1\n"					   \
		"	jnz 0b\n"					   \
		"1:	subq %1,%0\n"					   \
		"2:\n"							   \
		".section .fixup,\"ax\"\n"				   \
		"3:	movq %5,%0\n"					   \
		"	jmp 2b\n"					   \
		".previous\n"						   \
		".section __ex_table,\"a\"\n"				   \
		"	.align 8\n"					   \
		"	.quad 0b,3b\n"					   \
		".previous"						   \
		: "=r"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1),	   \
		  "=&D" (__d2)						   \
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst) \
		: "memory");						   \
} while (0)
#elif defined (__powerpc__) || defined (__arm__)
#define __stp_strncpy_from_user(dst,src,count,res) \
	do { res = __strncpy_from_user(dst, src, count); } while(0)

#elif defined (__s390__) || defined (__s390x__)|| defined (__aarch64__)
#define __stp_strncpy_from_user(dst,src,count,res) \
	do { res = strncpy_from_user(dst, src, count); } while(0)
#elif defined (__ia64__)
#define __stp_strncpy_from_user(dst,src,count,res)		\
	do { res = __strncpy_from_user(dst, src, count); } while(0)
#endif
#endif	/* !CONFIG_GENERIC_STRNCPY_FROM_USER */


/** Copy a NULL-terminated string from userspace.
 * On success, returns the length of the string (not including the trailing
 * NULL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 * @param dst Destination address, in kernel space.  This buffer must be at
 *         least <i>count</i> bytes long.
 * @param src Source address, in user space.
 * @param count Maximum number of bytes to copy, including the trailing NULL.
 * 
 * If <i>count</i> is smaller than the length of the string, copies 
 * <i>count</i> bytes and returns <i>count</i>.
 */

/* XXX: see also kread/uread in loc2c-runtime.h */
static long _stp_strncpy_from_user(char *dst, const char __user *src, long count)
{
	long res = -EFAULT;
        mm_segment_t _oldfs = get_fs();
        set_fs(USER_DS);
        pagefault_disable();
	if (access_ok(VERIFY_READ, src, count)) /* XXX: bad_addr? */
		__stp_strncpy_from_user(dst, src, count, res);
        pagefault_enable();
        set_fs(_oldfs);
	return res;
}

/** Copy a block of data from user space.
 *
 * If data could not be copied, this function will not modify the
 * destination.
 *
 * @param dst Destination address, in kernel space.
 * @param src Source address, in user space.
 * @param count Number of bytes to copy.
 * @return number of bytes that could not be copied. On success, 
 * this will be zero.
 *
 */

/* XXX: see also kread/uread in loc2c-runtime.h */
static unsigned long _stp_copy_from_user(char *dst, const char __user *src, unsigned long count)
{
	if (count) {
                mm_segment_t _oldfs = get_fs();
                set_fs(USER_DS);
                pagefault_disable();
		if (access_ok(VERIFY_READ, src, count))
			count = __copy_from_user_inatomic(dst, src, count);
		else
			/* Notice that if we fail, we don't modify
			 * the destination. In the failure case, we
			 * can't trust 'count' to be reasonable. */
			count = -EFAULT;
                pagefault_enable();
                set_fs(_oldfs);
	}
	return count;
}

/** @} */
#endif /* _STAPLINUX_COPY_C_ */
