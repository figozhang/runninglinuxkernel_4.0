/* -*- linux-c -*- 
 * Copyright (C) 2011 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_VSPRINTF_H_
#define _STP_VSPRINTF_H_

enum print_flag { STP_ZEROPAD=1, STP_SIGN=2, STP_PLUS=4, STP_SPACE=8,
		  STP_LEFT=16, STP_SPECIAL=32, STP_LARGE=64 };

static char *number(char * buf, char * end, uint64_t num, int base,
		    int size, int precision, enum print_flag type);
static int number_size(uint64_t num, int base, int size, int precision,
		       enum print_flag type);

static char *_stp_vsprint_char(char * str, char * end, char c,
			       int width, enum print_flag flags);
static int _stp_vsprint_char_size(char c, int width, enum print_flag flags);

static char *_stp_vsprint_memory(char * str, char * end, const char * ptr,
				 int width, int precision,
				 char format, enum print_flag flags);
static int _stp_vsprint_memory_size(const char * ptr, int width, int precision,
				    char format, enum print_flag flags);

static char *_stp_vsprint_binary(char * str, char * end, int64_t num,
				 int width, int precision,
				 enum print_flag flags);
static int _stp_vsprint_binary_size(int64_t num, int width, int precision);

static int _stp_vsnprintf(char *buf, size_t size, const char *fmt,
			  va_list args);

#include "transport/transport.h"

#endif /* _STP_VSPRINTF_H_ */
