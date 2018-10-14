/*
 * uidgid.h compatibility defines and inlines
 * Copyright (C) 2013 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _UIDGID_COMPATIBILITY_H_
#define _UIDGID_COMPATIBILITY_H_

#ifndef STAPCONF_LINUX_UIDGID_H

#define KUIDT_INIT(value) ((uid_t) value)
#define KGIDT_INIT(value) ((gid_t) value)

#else

#include <linux/cred.h>
#include <linux/uidgid.h>

#endif

#endif	/* _UIDGID_COMPATIBILITY_H_ */
