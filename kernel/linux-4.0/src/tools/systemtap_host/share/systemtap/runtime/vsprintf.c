/* -*- linux-c -*-
 * vsprintf.c
 * Copyright (C) 2006, 2008 Red Hat Inc.
 * Based on code from the Linux kernel
 * Copyright (C) 1991, 1992  Linus Torvalds
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _VSPRINTF_C_
#define _VSPRINTF_C_

#include "print.h"

static int skip_atoi(const char **s)
{
	int i=0;
	while (isdigit(**s))
		i = i*10 + *((*s)++) - '0';
	return i;
}

/*
 * Changes to number() will require a corresponding change to number_size below,
 * to ensure proper buffer allocation for _stp_printf.
 */
noinline static char * 
number(char * buf, char * end, uint64_t num, int base, int size, int precision, enum print_flag type)
{
	char c,sign,tmp[66];
	const char *digits;
	static const char small_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	static const char large_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int i;

	digits = (type & STP_LARGE) ? large_digits : small_digits;
	if (type & STP_LEFT)
		type &= ~STP_ZEROPAD;
	if (base < 2 || base > 36)
		return NULL;
	c = (type & STP_ZEROPAD) ? '0' : ' ';
	sign = 0;
	if (type & STP_SIGN) {
		if ((int64_t) num < 0) {
			sign = '-';
			num = - (int64_t) num;
			size--;
		} else if (type & STP_PLUS) {
			sign = '+';
			size--;
		} else if (type & STP_SPACE) {
			sign = ' ';
			size--;
		}
	}
	if (type & STP_SPECIAL) {
		if (base == 16)
			size -= 2;
		else if (base == 8)
			size--;
	}
	i = 0;
	if (num == 0)
		tmp[i++]='0';
	else while (num != 0)
		tmp[i++] = digits[do_div(num,base)];
	if (i > precision)
		precision = i;
	size -= precision;
	if (!(type&(STP_ZEROPAD+STP_LEFT))) {
		while(size-->0) {
			if (buf <= end)
				*buf = ' ';
			++buf;
		}
	}
	if (sign) {
		if (buf <= end)
			*buf = sign;
		++buf;
	}
	if (type & STP_SPECIAL) {
		if (base==8) {
			if (buf <= end)
				*buf = '0';
			++buf;
		} else if (base==16) {
			if (buf <= end)
				*buf = '0';
			++buf;
			if (buf <= end)
				*buf = digits[33];
			++buf;
		}
	}
	if (!(type & STP_LEFT)) {
		while (size-- > 0) {
			if (buf <= end)
				*buf = c;
			++buf;
		}
	}
	while (i < precision--) {
		if (buf <= end)
			*buf = '0';
		++buf;
	}
	while (i-- > 0) {
		if (buf <= end)
			*buf = tmp[i];
		++buf;
	}
	while (size-- > 0) {
		if (buf <= end)
			*buf = ' ';
		++buf;
	}
	return buf;
}

/*
 * Calculates the number of bytes required to print the paramater num. A change to 
 * number() requires a corresponding change here, and vice versa, to ensure the 
 * calculated size and printed size match.
 */
noinline static int
number_size(uint64_t num, int base, int size, int precision, enum print_flag type) {
    char c,sign,tmp[66];
    const char *digits;
    static const char small_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    static const char large_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int i, num_bytes = 0;

    digits = (type & STP_LARGE) ? large_digits : small_digits;
    if (type & STP_LEFT)
            type &= ~STP_ZEROPAD;
    if (base < 2 || base > 36)
            return 0;
    c = (type & STP_ZEROPAD) ? '0' : ' ';
    sign = 0;
    if (type & STP_SIGN) {
            if ((int64_t) num < 0) {
                    sign = '-';
                    num = - (int64_t) num;
                    size--;
            } else if (type & STP_PLUS) {
                    sign = '+';
                    size--;
            } else if (type & STP_SPACE) {
                    sign = ' ';
                    size--;
            }
    }
    if (type & STP_SPECIAL) {
            if (base == 16)
                    size -= 2;
            else if (base == 8)
                    size--;
    }
    i = 0;
    if (num == 0)
            tmp[i++]='0';
    else while (num != 0)
            tmp[i++] = digits[do_div(num,base)];
    if (i > precision)
            precision = i;
    size -= precision;
    if (!(type&(STP_ZEROPAD+STP_LEFT))) {
            while(size-->0) {
              num_bytes++;
            }
    }
    if (sign) {
      num_bytes++;
    }
    if (type & STP_SPECIAL) {
            if (base==8) {
                    num_bytes++;
            } else if (base==16) {
                    num_bytes+=2;
            }
    }
    if (!(type & STP_LEFT)) {
            while (size-- > 0) {
                    num_bytes++;
            }
    }
    while (i < precision--) {
            num_bytes++;
    }
    while (i-- > 0) {
            num_bytes++;
    }
    while (size-- > 0) {
            num_bytes++;
    }
    return num_bytes;

}


/*
 * Output one character into the buffer.  Usually this is just a
 * straight copy, padded left or right up to 'width', but if the user
 * gave the '#' flag then we need to escape special characters.
 */
noinline static char *
_stp_vsprint_char(char * str, char * end, char c,
		  int width, enum print_flag flags)
{
	int size = _stp_vsprint_char_size(c, 0, flags);

	if (!(flags & STP_LEFT)) {
		while (width-- > size) {
			if (str <= end)
				*str = ' ';
			++str;
		}
	}

	if (size == 1) {
		if (str <= end)
			*str = c;
		++str;
	}
	else {
		/* Other sizes mean this is not a printable character.
		 * First try to match up C escape characters: */
		char escape = 0;
		switch (c) {
			case '\a':
				escape = 'a';
				break;
			case '\b':
				escape = 'b';
				break;
			case '\f':
				escape = 'f';
				break;
			case '\n':
				escape = 'n';
				break;
			case '\r':
				escape = 'r';
				break;
			case '\t':
				escape = 't';
				break;
			case '\v':
				escape = 'v';
				break;
			case '\'':
				escape = '\'';
				break;
			case '\\':
				escape = '\\';
				break;
		}

		if (str <= end)
			*str = '\\';
		++str;
		if (escape) {
			if (str <= end)
				*str = escape;
			++str;
		}
		else {
			/* Fall back to octal for everything else */
			if (str <= end)
				*str = to_oct_digit((c >> 6) & 03);
			++str;
			if (str <= end)
				*str = to_oct_digit((c >> 3) & 07);
			++str;
			if (str <= end)
				*str = to_oct_digit(c & 07);
			++str;
		}
	}

	while (width-- > size) {
		if (str <= end)
			*str = ' ';
		++str;
	}

	return str;
}


/*
 * Compute the size of a given character in the buffer.  Usually this is
 * just 1 (padded up to 'width'), but if the user gave the '#' flag then
 * we need to escape special characters.
 */
noinline static int
_stp_vsprint_char_size(char c, int width, enum print_flag flags)
{
	int size = 1;

	/* look for quoteworthy characters */
	if ((flags & STP_SPECIAL) &&
	    (!(isprint(c) && isascii(c)) || c == '\'' || c == '\\'))
		switch (c) {
			case '\a':
			case '\b':
			case '\f':
			case '\n':
			case '\r':
			case '\t':
			case '\v':
			case '\'':
			case '\\':
				/* backslash and one escape character */
				size = 2;
				break;
			default:
				/* backslash and three octal digits */
				size = 4;
				break;
		}

	return max(size, width);
}


noinline static char *
_stp_vsprint_memory(char * str, char * end, const char * ptr,
		    int width, int precision,
		    char format, enum print_flag flags)
{
	int i, len = 0;
	struct context * __restrict__ c;

	if (format == 's') {
		if ((unsigned long)ptr < PAGE_SIZE)
			ptr = "<NULL>";
		len = strnlen(ptr, precision);
	}
	else if (precision > 0)
		len = precision;
	else
		len = 1;

	if (!(flags & STP_LEFT)) {
		int actlen = len;
		if (format == 'M')
			actlen = len * 2;
		while (actlen < width-- && str <= end)
			*str++ = ' ';
	}

	if (format == 'M') { /* stolen from kernel: trace_seq_putmem_hex() */
		static const char _stp_hex_asc[] = "0123456789abcdef";

                /* PR13386: Skip if called with null context */
		c = _stp_runtime_get_context();
                if (c) for (i = 0; i < len && str < end; i++) {
			unsigned char c_tmp = kread((unsigned char *)(ptr));
			ptr++;
			*str++ = _stp_hex_asc[(c_tmp & 0xf0) >> 4];
			*str++ = _stp_hex_asc[(c_tmp & 0x0f)];
		}
		len = len * 2; /* the actual length */
	}
	else if (format == 'm') {
                /* PR13386: Skip if called with null context */
		c = _stp_runtime_get_context();
		if (c) for (i = 0; i < len && str <= end; ++i) {
			*str++ = kread((unsigned char *)(ptr));
			ptr++;
		}
	}
	else				/* %s format */
		for (i = 0; i < len && str <= end; ++i)
			*str++ = *ptr++;

	while (len < width-- && str <= end)
		*str++ = ' ';

	if (flags & STP_ZEROPAD && str <= end)
		*str++ = '\0';

	return str;

	/* We've caught a deref fault.  Make sure the string is null
	 * terminated. and return. */
deref_fault:
	if (str <= end)
		*str = '\0';
	return NULL;
}

noinline static int
_stp_vsprint_memory_size(const char * ptr, int width, int precision,
			 char format, enum print_flag flags)
{
	int len = 0;

	if (format == 's') {
		if ((unsigned long)ptr < PAGE_SIZE)
			ptr = "<NULL>";
		len = strnlen(ptr, precision);
	}
	else if (precision > 0)
		len = precision;
	else
		len = 1;

	if (format == 'M')
		len = len * 2; /* hex dump print size */

	len = max(len, width);

	if (flags & STP_ZEROPAD)
		len++;

	return len;
}

static int check_binary_precision (int precision) {
  /* precision can be unspecified (-1) or one of 1, 2, 4 or 8.  */
  switch (precision) {
  case -1:
  case 1:
  case 2:
  case 4:
  case 8:
    break;
  default:
    precision = -1;
    break;
  }
  return precision;
}

noinline static char *
_stp_vsprint_binary(char * str, char * end, int64_t num,
		    int width, int precision, enum print_flag flags)
{
	/* Only certain values are valid for the precision.  */
	precision = check_binary_precision (precision);

	/* Unspecified field width defaults to the specified
	   precision and vice versa. If neither is specified,
	   then both default to 8.  */
	if (width == -1) {
		if (precision == -1) {
			width = 8;
			precision = 8;
		}
		else
			width = precision;
	}
	else if (precision == -1) {
		precision = check_binary_precision (width);
		if (precision == -1)
			precision = 8;
	}

	if (!(flags & STP_LEFT))
		while (precision < width-- && str <= end)
			*str++ = '\0';

	if ((str + precision - 1) <= end) {
#ifdef __ia64__
		memcpy(str, &num, precision); //to prevent unaligned access
#else
		switch(precision) {
			case 1:
				*(int8_t *)str = (int8_t)num;
				break;
			case 2:
				*(int16_t *)str = (int16_t)num;
				break;
			case 4:
				*(int32_t *)str = (int32_t)num;
				break;
			default: // "%.8b" by default
			case 8:
				*(int64_t *)str = num;
				break;
		}
#endif
		str += precision;
	}

	while (precision < width-- && str <= end)
		*str++ = '\0';

	return str;
}

noinline static int
_stp_vsprint_binary_size(int64_t num, int width, int precision)
{
	/* Only certain values are valid for the precision.  */
	precision = check_binary_precision (precision);

	/* Unspecified field width defaults to the specified
	   precision and vice versa. If neither is specified,
	   then both default to 8.  */
	if (width == -1) {
		if (precision == -1) {
			width = 8;
			precision = 8;
		}
		else
			width = precision;
	}
	else if (precision == -1) {
		precision = check_binary_precision (width);
		if (precision == -1)
			precision = 8;
	}

	return max(precision, width);
}

noinline static int
_stp_vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int len;
	uint64_t num;
	int i, base;
	char *str = NULL, *end = NULL, c;
	const char *s;
	enum print_flag flags;		/* flags to number() */
	int field_width;	/* width of output field */
	int precision;		/* min. # of digits for integers; max
				   number of chars for from string */
	int qualifier;		/* 'h', 'l', or 'L' for integer fields */
	int num_bytes = 0;

	/* Reject out-of-range values early */
	if (unlikely((int) size < 0))
		return 0;

	/*
	 * buf will be NULL when this function is called from _stp_printf.
	 * This branch calculates the exact size print buffer required for 
	 * the string and allocates it with _stp_reserve_bytes. A change
	 * to this branch requires a corresponding change to the same 
	 * section of code below.
	 */
	if (buf == NULL) {
	  const char* fmt_copy = fmt;
          va_list args_copy;

          va_copy(args_copy, args);

          for (; *fmt_copy ; ++fmt_copy) {
                    if (*fmt_copy != '%') {
                            num_bytes++;
                            continue;
                    }

                    /* process flags */
                    flags = 0;
            repeat_copy:
                    ++fmt_copy;          /* this also skips first '%' */
                    switch (*fmt_copy) {
                    case '-': flags |= STP_LEFT; goto repeat_copy;
                    case '+': flags |= STP_PLUS; goto repeat_copy;
                    case ' ': flags |= STP_SPACE; goto repeat_copy;
                    case '#': flags |= STP_SPECIAL; goto repeat_copy;
                    case '0': flags |= STP_ZEROPAD; goto repeat_copy;
                    }

                    /* get field width */
                    field_width = -1;
                    if (isdigit(*fmt_copy))
                            field_width = clamp(skip_atoi(&fmt_copy), 0, STP_BUFFER_SIZE);
                    else if (*fmt_copy == '*') {
                            ++fmt_copy;
                            /* it's the next argument */
                            field_width = va_arg(args_copy, int);
                            if (field_width < 0) {
                                    field_width = -field_width;
                                    flags |= STP_LEFT;
                            }
                            field_width = clamp(field_width, 0, STP_BUFFER_SIZE);
                    }

                    /* get the precision */
                    precision = -1;
                    if (*fmt_copy == '.') {
                            ++fmt_copy;
                            if (isdigit(*fmt_copy))
                                    precision = skip_atoi(&fmt_copy);
                            else if (*fmt_copy == '*') {
                                    ++fmt_copy;
                                    /* it's the next argument */
                                    precision = va_arg(args_copy, int);
                            }
                            precision = clamp(precision, 0, STP_BUFFER_SIZE);
                    }

                    /* get the conversion qualifier */
                    qualifier = -1;
                    if (*fmt_copy == 'h' || *fmt_copy == 'l' || *fmt_copy == 'L') {
                            qualifier = *fmt_copy;
                            ++fmt_copy;
                            if (qualifier == 'l' && *fmt_copy == 'l') {
                                    qualifier = 'L';
                                    ++fmt_copy;
                            }
                    }

                    /* default base */
                    base = 10;

                    switch (*fmt_copy) {
                    case 'b':
                            num = va_arg(args_copy, int64_t);
                            num_bytes += _stp_vsprint_binary_size(num,
                                            field_width, precision);
                            continue;

                    case 's':
                    case 'M':
                    case 'm':
                            s = va_arg(args_copy, char *);
                            num_bytes += _stp_vsprint_memory_size(s,
                                            field_width, precision,
                                            *fmt_copy, flags);
                            continue;

                    case 'X':
                            flags |= STP_LARGE;
                    case 'x':
                            base = 16;
                            break;

                    case 'd':
                    case 'i':
                            flags |= STP_SIGN;
                    case 'u':
                            break;

                    case 'p':
                            /* Note that %p takes an int64_t argument. */
                            qualifier = 'L';
                            /* Since stap 1.3, %p == %#x. */
                            flags |= STP_SPECIAL;
                            base = 16;

#if STAP_COMPAT_VERSION < STAP_VERSION(1,3)
                            /* Before 1.3, %p was an odd child; see below. */
                            qualifier = 'P';
                            if (field_width == -1)
                                    field_width = 2 + 2*sizeof(void*);
                            precision = field_width - 2;
                            if (!(flags & STP_LEFT))
                                    precision = min_t(int, precision, 2*sizeof(void*));
#endif

                            break;

                    case '%':
                            num_bytes++;
                            continue;

                            /* integer number formats - set up the flags and "break" */
                    case 'o':
                            base = 8;
                            break;

                    case 'c':
                            c = (unsigned char) va_arg(args_copy, int);
                            num_bytes += _stp_vsprint_char_size(c, field_width, flags);
                            continue;

                    default:
                            num_bytes++;
                            if (*fmt_copy) {
                              num_bytes++;
                            } else {
                              --fmt_copy;
                            }
                            continue;
                    }

                    if (qualifier == 'L')
                            num = va_arg(args_copy, int64_t);
                    else if (qualifier == 'P') // fake, just for compat %p
                            num = (unsigned long) va_arg(args_copy, int64_t);
                    else if (qualifier == 'l') {
                            num = va_arg(args_copy, unsigned long);
                            if (flags & STP_SIGN)
                                    num = (signed long) num;
                    } else if (qualifier == 'h') {
                            num = (unsigned short) va_arg(args_copy, int);
                            if (flags & STP_SIGN)
                                    num = (signed short) num;
                    } else {
                            num = va_arg(args_copy, unsigned int);
                            if (flags & STP_SIGN)
                                    num = (signed int) num;
                    }
                    num_bytes += number_size(num, base, field_width, precision, flags);
            }

	  va_end(args_copy);

	  if (num_bytes == 0)
	    return 0;

	  //max print buffer size
	  if (num_bytes > STP_BUFFER_SIZE) {
	    num_bytes = STP_BUFFER_SIZE;
	  }

	  str = (char*)_stp_reserve_bytes(num_bytes);
	  if (str == NULL) {
	    _stp_error("Couldn't reserve any print buffer space\n");
	    return 0;
	  }
	  size = num_bytes;
	  end = str + size - 1;

	} else {
          str = buf;
          end = buf + size - 1;
	}

	/*
	 * Note that a change to code below requires a corresponding
	 * change in the code above to properly calculate the bytes
	 * required in the output buffer.
	 */
	for (; *fmt ; ++fmt) {
		if (*fmt != '%') {
			if (str <= end)
				*str = *fmt;
			++str;
			continue;
		}

		/* process flags */
		flags = 0;
	repeat:
		++fmt;          /* this also skips first '%' */
		switch (*fmt) {
		case '-': flags |= STP_LEFT; goto repeat;
		case '+': flags |= STP_PLUS; goto repeat;
		case ' ': flags |= STP_SPACE; goto repeat;
		case '#': flags |= STP_SPECIAL; goto repeat;
		case '0': flags |= STP_ZEROPAD; goto repeat;
		}

		/* get field width */
		field_width = -1;
		if (isdigit(*fmt))
			field_width = clamp(skip_atoi(&fmt), 0, (int)size);
		else if (*fmt == '*') {
			++fmt;
			/* it's the next argument */
			field_width = va_arg(args, int);
			if (field_width < 0) {
				field_width = -field_width;
				flags |= STP_LEFT;
			}
			field_width = clamp(field_width, 0, (int)size);
		}

		/* get the precision */
		precision = -1;
		if (*fmt == '.') {
			++fmt;
			if (isdigit(*fmt))
				precision = skip_atoi(&fmt);
			else if (*fmt == '*') {
				++fmt;
				/* it's the next argument */
				precision = va_arg(args, int);
			}
			precision = clamp(precision, 0, (int)size);
		}

		/* get the conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L') {
			qualifier = *fmt;
			++fmt;
			if (qualifier == 'l' && *fmt == 'l') {
				qualifier = 'L';
				++fmt;
			}
		}

		/* default base */
		base = 10;

		switch (*fmt) {
		case 'b':
			num = va_arg(args, int64_t);
			str = _stp_vsprint_binary(str, end, num,
					field_width, precision, flags);
			continue;

		case 's':
	        case 'M':
		case 'm':
			s = va_arg(args, char *);
			str = _stp_vsprint_memory(str, end, s,
					field_width, precision,
					*fmt, flags);
			if (unlikely(str == NULL)) {
				if (num_bytes > 0)
					_stp_unreserve_bytes(num_bytes);
				return 0;
			}
			continue;

		case 'X':
			flags |= STP_LARGE;
		case 'x':
			base = 16;
			break;

		case 'd':
		case 'i':
			flags |= STP_SIGN;
		case 'u':
			break;

		case 'p':
			/* Note that %p takes an int64_t argument. */
			qualifier = 'L';
			/* Since stap 1.3, %p == %#x. */
			flags |= STP_SPECIAL;
			base = 16;

#if STAP_COMPAT_VERSION < STAP_VERSION(1,3)
			/* Before 1.3, %p was an odd child:
			 * - the value is truncated to unsigned long
			 * - the specified precision is ignored
			 * - the default field_width is 2+2*sizeof(void*)
			 * - the effective precision is field_width - 2, except
			 *   if !STP_LEFT, where it is at most 2*sizeof(void*)
			 */
			qualifier = 'P';
			if (field_width == -1)
				field_width = 2 + 2*sizeof(void*);
			precision = field_width - 2;
			if (!(flags & STP_LEFT))
				precision = min_t(int, precision, 2*sizeof(void*));
#endif

			break;

		case '%':
			if (str <= end)
				*str = '%';
			++str;
			continue;

			/* integer number formats - set up the flags and "break" */
		case 'o':
			base = 8;
			break;

		case 'c':
			c = (unsigned char) va_arg(args, int);
			str = _stp_vsprint_char(str, end, c, field_width, flags);
			continue;

		default:
			if (str <= end)
				*str = '%';
			++str;
			if (*fmt) {
				if (str <= end)
					*str = *fmt;
				++str;
			} else {
				--fmt;
			}
			continue;
		}

		if (qualifier == 'L')
			num = va_arg(args, int64_t);
		else if (qualifier == 'P') // fake, just for compat %p
			num = (unsigned long) va_arg(args, int64_t);
		else if (qualifier == 'l') {
			num = va_arg(args, unsigned long);
			if (flags & STP_SIGN)
				num = (signed long) num;
		} else if (qualifier == 'h') {
			num = (unsigned short) va_arg(args, int);
			if (flags & STP_SIGN)
				num = (signed short) num;
		} else {
			num = va_arg(args, unsigned int);
			if (flags & STP_SIGN)
				num = (signed int) num;
		}
		str = number(str, end, num, base,
			     field_width, precision, flags);
	}

	if (buf != NULL) {
          if (likely(str <= end))
                  *str = '\0';
          else if (size > 0)
                  /* don't write out a null byte if the buf size is zero */
                  *end = '\0';
	}
	return str-buf;
}

#endif /* _VSPRINTF_C_ */
