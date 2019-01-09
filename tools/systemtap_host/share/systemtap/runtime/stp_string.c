/* -*- linux-c -*- 
 * String Functions
 * Copyright (C) 2005, 2006, 2007, 2009, 2015 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _STP_STRING_C_
#define _STP_STRING_C_

#include "stp_string.h"

/** @file stp_string.c
 * @brief Implements string functions.
 */
/** @addtogroup string String Functions
 *
 * @{
 */

/** Sprintf into a string.
 * Like printf, except output goes into a string.  
 *
 * NB: these are script language printf formatting directives, where
 * %d ints are 64-bits etc, so we can't use gcc level attribute printf
 * to type-check the arguments.
 *
 * @param str string
 * @param fmt A printf-style format string followed by a 
 * variable number of args.
 */

static int _stp_snprintf(char *buf, size_t size, const char *fmt, ...)
{
        va_list args;
        int i;

        va_start(args, fmt);
        i = _stp_vsnprintf(buf,size,fmt,args);
        va_end(args);
        return i;
}

static int _stp_vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	unsigned i = _stp_vsnprintf(buf,size,fmt,args);
	return (i >= size) ? (size - 1) : i;
}


/**
 * Decode a UTF-8 sequence into its codepoint.
 *
 * @param buf The input buffer.
 * @param size The size of the input buffer.
 * @param user Flag to mark user memory, vs kernel.
 * @param c_ret The return pointer for the codepoint.
 *
 * @return The number of bytes consumed,
 * 	   or -EFAULT for unreadable memory address.
 */
static int _stp_decode_utf8(const char* buf, int size, int user, int* c_ret)
{
	int c;
	char b = '\0';
	int i, n;

	if (size <= 0)
		return -EFAULT;

	if (_stp_read_address(b, buf, (user ? USER_DS : KERNEL_DS)))
		return -EFAULT;
	++buf;
	--size;

	if ((b & 0xE0) == 0xC0 && size >= 1) {
		/* 110xxxxx 10xxxxxx */
		/* Two-byte UTF-8, one more byte to read.  */
		n = 2;
		c = b & 0x1F;
	} else if ((b & 0xF0) == 0xE0 && size >= 2) {
		/* 1110xxxx 10xxxxxx 10xxxxxx */
		/* Three-byte UTF-8, two more bytes to read.  */
		n = 3;
		c = b & 0xF;
	} else if ((b & 0xF8) == 0xF0 && size >= 3) {
		/* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
		/* Four-byte UTF-8, three more bytes to read.  */
		n = 4;
		c = b & 0x7;
	} else {
		/* Return everything else verbatim, whether it's ASCII, longer
		 * UTF-8 (against RFC 3629), invalid UTF-8, or just not enough
		 * bytes left in the input buffer.  */
		goto verbatim;
	}

	/* Mix in the UTF-8 continuation bytes.  */
	for (i = 1; i < n; ++i) {
		char b2 = '\0';
		if (_stp_read_address(b2, buf, (user ? USER_DS : KERNEL_DS)))
			return -EFAULT;
		++buf;
		--size;

		if ((b2 & 0xC0) != 0x80) /* Bad continuation.  */
			goto verbatim;

		c = (c << 6) | (b2 & 0x3F);
	}


	/* Reject UTF-16 surrogates.  */
	if (0xD800 <= c && c <= 0xDFFF)
		goto verbatim;

	/* Reject values that exceed RFC 3629.  */
	if (c > 0x10FFFF)
		goto verbatim;

	/* Reject values that were encoded longer than necessary, so we don't
	 * hide that fact in our output.  (e.g. 0xC0 0x80 -> 0!)  */
	if (c < 0x80 || (n == 3 && c < 0x800) || (n == 4 && c < 0x10000))
		goto verbatim;

	/* Successfully consumed the continuation bytes.  */
	*c_ret = c;
	return n;

verbatim:
	*c_ret = (unsigned char) b;
	return 1;
}

/** Return a printable text string.
 *
 * Takes a string, and any ASCII characters that are not printable are
 * replaced by the corresponding escape sequence in the returned
 * string.
 *
 * @param outstr Output string pointer
 * @param in Input string pointer
 * @param inlen Maximum length of string to read not including terminating 0.
 * @param outlen Maximum length of string to return not including terminating 0.
 * 0 means MAXSTRINGLEN.
 * @param quoted Put double quotes around the string. If input string is truncated
 * in will have "..." after the second quote.
 * @param user Set this to indicate the input string pointer is a userspace pointer.
 */
static int _stp_text_str(char *outstr, const char *in, int inlen, int outlen,
			 int quoted, int user)
{
	int c = 0;
	char *out = outstr;

	if (inlen <= 0 || inlen > MAXSTRINGLEN-1)
		inlen = MAXSTRINGLEN-1;
	if (outlen <= 0 || outlen > MAXSTRINGLEN-1)
		outlen = MAXSTRINGLEN-1;
	if (quoted) {
		outlen = max(outlen, 5) - 2;
		*out++ = '"';
	}

	while (inlen > 0) {
		int num = 1;

		int n = _stp_decode_utf8(in, inlen, user, &c);
		if (n <= 0)
			goto bad;
		if (c == 0 || outlen <= 0)
			break;
		in += n;
		inlen -= n;

		if (n > 1) {
			/* UTF-8, print \uXXXX or \UXXXXXXXX */
			int i;
			num = (c <= 0xFFFF) ? 6 : 10;
			if (outlen < num)
				break;

			*out++ = '\\';
			*out++ = (c <= 0xFFFF) ? 'u' : 'U';
			for (i = num - 3; i >= 0; --i) {
				char nibble = (c >> (i * 4)) & 0xF;
				*out++ = to_hex_digit(nibble);
			}

		}
		else if (isascii(c) && isprint(c)
				&& c != '"' && c != '\\') /* quoteworthy characters */
			*out++ = c;
		else {
			switch (c) {
			case '\a':
			case '\b':
			case '\f':
			case '\n':
			case '\r':
			case '\t':
			case '\v':
			case '"':
			case '\\':
				num = 2; // "\c"
				break;
			default:
				num = 4; // "\ooo"
				break;
			}
			
			if (outlen < num)
				break;

			*out++ = '\\';
			switch (c) {
			case '\a':
				*out++ = 'a';
				break;
			case '\b':
				*out++ = 'b';
				break;
			case '\f':
				*out++ = 'f';
				break;
			case '\n':
				*out++ = 'n';
				break;
			case '\r':
				*out++ = 'r';
				break;
			case '\t':
				*out++ = 't';
				break;
			case '\v':
				*out++ = 'v';
				break;
			case '"':
				*out++ = '"';
				break;
			case '\\':
				*out++ = '\\';
				break;
			default:                  /* output octal representation */
				*out++ = to_oct_digit((c >> 6) & 03);
				*out++ = to_oct_digit((c >> 3) & 07);
				*out++ = to_oct_digit(c & 07);
				break;
			}
		}
		outlen -= num;
	}

	if (quoted) {
		if (c && inlen > 0) {
			out = out - 3 + outlen;
			*out++ = '"';
			*out++ = '.';
			*out++ = '.';
			*out++ = '.';
		} else
			*out++ = '"';
	}
	*out = '\0';
	return 0;
bad:
	strlcpy (outstr, "<unknown>", outlen);
	return -1; // PR15044
}

/**
 * Convert a UTF-32 character into a UTF-8 string.
 *
 * @param buf The output buffer.
 * @param size The size of the output buffer.
 * @param c The character to convert.
 *
 * @return The number of bytes written (not counting \0),
 *         0 if there's not enough room for the full character,
 *         or < 0 for invalid characters (with buf untouched).
 */
static int _stp_convert_utf32(char* buf, int size, u32 c)
{
	int i, n;

	/* 0xxxxxxx */
	if (c <= 0x7F)
		n = 1;

	/* 110xxxxx 10xxxxxx */
	else if (c <= 0x7FF)
		n = 2;

	/* UTF-16 surrogates are not valid by themselves.
	 * XXX We could decide to be lax and just encode it anyway...
	 */
	else if (c >= 0xD800 && c <= 0xDFFF)
		return -EINVAL;

	/* 1110xxxx 10xxxxxx 10xxxxxx */
	else if (c <= 0xFFFF)
		n = 3;

	/* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
	else if (c <= 0x10FFFF)
		n = 4;

	/* The original UTF-8 design could go up to 0x7FFFFFFF, but RFC 3629
	 * sets the upperbound to 0x10FFFF; thus all higher values are errors.
	 */
	else
		return -EINVAL;

	if (size < n + 1)
		return 0;

	buf[n] = '\0';
	if (n == 1)
		buf[0] = c;
	else {
		u8 msb = ((1 << n) - 1) << (8 - n);
		for (i = n - 1; i > 0; --i) {
			buf[i] = 0x80 | (c & 0x3F);
			c >>= 6;
		}
		buf[0] = msb | c;
	}

	return n;
}

/** @} */
#endif /* _STP_STRING_C_ */
