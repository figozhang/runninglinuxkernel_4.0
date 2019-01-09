/* -*- linux-c -*- 
 * Syscall compatibility defines.
 * Copyright (C) 2013-2014 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _COMPAT_UNISTD_H_
#define _COMPAT_UNISTD_H_

// Older kernels (like RHEL5) supported __NR_sendfile64. For newer
// kernels, we'll just define __NR_sendfile64 in terms of
// __NR_sendfile.
#ifndef __NR_sendfile64
#define __NR_sendfile64 __NR_sendfile
#endif

#ifndef __NR_syscall_max
#define __NR_syscall_max 0xffff
#endif

#ifndef __NR_accept
#define __NR_accept (__NR_syscall_max + 1)
#endif
#ifndef __NR_accept4
#define __NR_accept4 (__NR_syscall_max + 1)
#endif
#ifndef __NR_bind
#define __NR_bind (__NR_syscall_max + 1)
#endif
#ifndef __NR_connect
#define __NR_connect (__NR_syscall_max + 1)
#endif
#ifndef __NR_fadvise64_64
#define __NR_fadvise64_64 (__NR_syscall_max + 1)
#endif
#ifndef __NR_ftruncate
#define __NR_ftruncate (__NR_syscall_max + 1)
#endif
#ifndef __NR_futimesat
#define __NR_futimesat (__NR_syscall_max + 1)
#endif
#ifndef __NR_getpeername
#define __NR_getpeername (__NR_syscall_max + 1)
#endif
#ifndef __NR_getsockname
#define __NR_getsockname (__NR_syscall_max + 1)
#endif
#ifndef __NR_ipc
#define __NR_ipc (__NR_syscall_max + 1)
#endif
#ifndef __NR_listen
#define __NR_listen (__NR_syscall_max + 1)
#endif
#ifndef __NR_mmap2
#define __NR_mmap2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_move_pages
#define __NR_move_pages (__NR_syscall_max + 1)
#endif
#ifndef __NR_msgctl
#define __NR_msgctl (__NR_syscall_max + 1)
#endif
#ifndef __NR_open
#define __NR_open (__NR_syscall_max + 1)
#endif
#ifndef __NR_pselect7
#define __NR_pselect7 (__NR_syscall_max + 1)
#endif
#ifndef __NR_recv
#define __NR_recv (__NR_syscall_max + 1)
#endif
#ifndef __NR_recvfrom
#define __NR_recvfrom (__NR_syscall_max + 1)
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg (__NR_syscall_max + 1)
#endif
#ifndef __NR_send
#define __NR_send (__NR_syscall_max + 1)
#endif
#ifndef __NR_sendmmsg
#define __NR_sendmmsg (__NR_syscall_max + 1)
#endif
#ifndef __NR_sendmsg
#define __NR_sendmsg (__NR_syscall_max + 1)
#endif
#ifndef __NR_sendto
#define __NR_sendto (__NR_syscall_max + 1)
#endif
#ifndef __NR_getsockopt
#define __NR_getsockopt (__NR_syscall_max + 1)
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 (__NR_syscall_max + 1)
#endif
#ifndef __NR_setsockopt
#define __NR_setsockopt (__NR_syscall_max + 1)
#endif
#ifndef __NR_shutdown
#define __NR_shutdown (__NR_syscall_max + 1)
#endif
#ifndef __NR_sigprocmask
#define __NR_sigprocmask (__NR_syscall_max + 1)
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait (__NR_syscall_max + 1)
#endif
#ifndef __NR_shmctl
#define __NR_shmctl (__NR_syscall_max + 1)
#endif
#ifndef __NR_socket
#define __NR_socket (__NR_syscall_max + 1)
#endif
#ifndef __NR_socketpair
#define __NR_socketpair (__NR_syscall_max + 1)
#endif
#ifndef __NR_truncate
#define __NR_truncate (__NR_syscall_max + 1)
#endif

#if defined(__x86_64__)

// On older kernels (like RHEL5), we have to define our own 32-bit
// syscall numbers.
#ifndef __NR_ia32_chown32
#define __NR_ia32_chown32 212
#endif
#ifndef __NR_ia32_clone
#define __NR_ia32_clone 120
#endif
#ifndef __NR_ia32_close
#define __NR_ia32_close 6
#endif
#ifndef __NR_ia32_dup3
#define __NR_ia32_dup3 330
#endif
#ifndef __NR_ia32_epoll_wait
#define __NR_ia32_epoll_wait 256
#endif
#ifndef __NR_ia32_eventfd2
#define __NR_ia32_eventfd2 328
#endif
#ifndef __NR_ia32_faccessat
#define __NR_ia32_faccessat 307
#endif
#ifndef __NR_ia32_fchmodat
#define __NR_ia32_fchmodat 306
#endif
#ifndef __NR_ia32_fchown32
#define __NR_ia32_fchown32 207
#endif
#ifndef __NR_ia32_fchownat
#define __NR_ia32_fchownat 298
#endif
#ifndef __NR_ia32_ftruncate
#define __NR_ia32_ftruncate 93
#endif
#ifndef __NR_ia32_futimesat
#define __NR_ia32_futimesat 299
#endif
#ifndef __NR_ia32_getpgid
#define __NR_ia32_getpgid 132
#endif
#ifndef __NR_ia32_inotify_init1
#define __NR_ia32_inotify_init1 332
#endif
#ifndef __NR_ia32_linkat
#define __NR_ia32_linkat 303
#endif
#ifndef __NR_ia32_lchown32
#define __NR_ia32_lchown32 198
#endif
#ifndef __NR_ia32_mkdirat
#define __NR_ia32_mkdirat 296
#endif
#ifndef __NR_ia32_mknodat
#define __NR_ia32_mknodat 297
#endif
#ifndef __NR_ia32_mmap2
#define __NR_ia32_mmap2 192
#endif
#ifndef __NR_ia32_open
#define __NR_ia32_open 5
#endif
#ifndef __NR_ia32_pipe2
#define __NR_ia32_pipe2 331
#endif
#ifndef __NR_ia32_pselect7
// Since a kernel that had a pselect7 syscall can't be found, just use
// __NR_syscall_max for __NR_ia32_pselect7.
#define __NR_ia32_pselect7 (__NR_syscall_max + 1)
#endif
#ifndef __NR_ia32_readlinkat
#define __NR_ia32_readlinkat 305
#endif
#ifndef __NR_ia32_renameat
#define __NR_ia32_renameat 302
#endif
#ifndef __NR_ia32_renameat2
#define __NR_ia32_renameat2 353
#endif
#ifndef __NR_ia32_rt_sigprocmask
#define __NR_ia32_rt_sigprocmask 175
#endif
#ifndef __NR_ia32_sendmmsg
#define __NR_ia32_sendmmsg 345
#endif
// Since a kernel that had a 32-biy shmctl syscall can't be found
// (they all used __NR_ipc), just use __NR_syscall_max.
#ifndef __NR_ia32_shmctl
#define __NR_ia32_shmctl (__NR_syscall_max + 1)
#endif
#ifndef __NR_ia32_symlinkat
#define __NR_ia32_symlinkat 304
#endif
#ifndef __NR_ia32_truncate
#define __NR_ia32_truncate 92
#endif
#ifndef __NR_ia32_umount2
#define __NR_ia32_umount2 52
#endif
#ifndef __NR_ia32_wait4
#define __NR_ia32_wait4 114
#endif

#define __NR_compat_clone		__NR_ia32_clone
#define __NR_compat_close		__NR_ia32_close
#define __NR_compat_dup3		__NR_ia32_dup3
#define __NR_compat_epoll_wait		__NR_ia32_epoll_wait
#define __NR_compat_eventfd2		__NR_ia32_eventfd2
#define __NR_compat_faccessat		__NR_ia32_faccessat
#define __NR_compat_fchmodat		__NR_ia32_fchmodat
#define __NR_compat_fchownat		__NR_ia32_fchownat
#define __NR_compat_ftruncate		__NR_ia32_ftruncate
#define __NR_compat_futimesat		__NR_ia32_futimesat
#define __NR_compat_getpgid		__NR_ia32_getpgid
#define __NR_compat_inotify_init1	__NR_ia32_inotify_init1
#define __NR_compat_linkat		__NR_ia32_linkat
#define __NR_compat_mkdirat		__NR_ia32_mkdirat
#define __NR_compat_mknodat		__NR_ia32_mknodat
#define __NR_compat_open		__NR_ia32_open
#define __NR_compat_pipe2		__NR_ia32_pipe2
#define __NR_compat_pselect7		__NR_ia32_pselect7
#define __NR_compat_readlinkat		__NR_ia32_readlinkat
#define __NR_compat_renameat		__NR_ia32_renameat
#define __NR_compat_renameat2		__NR_ia32_renameat2
#define __NR_compat_rt_sigprocmask	__NR_ia32_rt_sigprocmask
#define __NR_compat_sendmmsg		__NR_ia32_sendmmsg
#define __NR_compat_shmctl		__NR_ia32_shmctl
#define __NR_compat_symlinkat		__NR_ia32_symlinkat
#define __NR_compat_truncate		__NR_ia32_truncate
#define __NR_compat_umount2		__NR_ia32_umount2
#define __NR_compat_wait4		__NR_ia32_wait4

#endif	/* __x86_64__ */

#if defined(__powerpc64__) || defined (__s390x__) || defined(__aarch64__)

// On the ppc64 and s390x, the 32-bit syscalls use the same number
// as the 64-bit syscalls.
//
// On arm64, the 32-bit syscall *can* use different numbers than the
// 64-bit syscalls, but the majority do not. The following syscalls
// use the same number.

#define __NR_compat_clone		__NR_clone
#define __NR_compat_close		__NR_close
#define __NR_compat_dup3		__NR_dup3
#define __NR_compat_epoll_wait		__NR_epoll_wait
#define __NR_compat_eventfd2		__NR_eventfd2
#define __NR_compat_faccessat		__NR_faccessat
#define __NR_compat_fchmodat		__NR_fchmodat
#define __NR_compat_fchownat		__NR_fchownat
#define __NR_compat_ftruncate		__NR_ftruncate
#define __NR_compat_futimesat		__NR_futimesat
#define __NR_compat_getpgid		__NR_getpgid
#define __NR_compat_inotify_init1	__NR_inotify_init1
#define __NR_compat_linkat		__NR_linkat
#define __NR_compat_mkdirat		__NR_mkdirat
#define __NR_compat_mknodat		__NR_mknodat
#define __NR_compat_open		__NR_open
#define __NR_compat_pipe2		__NR_pipe2
#define __NR_compat_pselect7		__NR_pselect7
#define __NR_compat_readlinkat		__NR_readlinkat
#define __NR_compat_renameat		__NR_renameat
#define __NR_compat_renameat2		__NR_renameat2
#define __NR_compat_rt_sigprocmask	__NR_rt_sigprocmask
#define __NR_compat_sendmmsg		__NR_sendmmsg
#define __NR_compat_shmctl		__NR_shmctl
#define __NR_compat_symlinkat		__NR_symlinkat
#define __NR_compat_truncate		__NR_truncate
#define __NR_compat_umount2		__NR_umount2
#define __NR_compat_wait4		__NR_wait4

#endif	/* __powerpc64__ || __s390x__ || __aarch64__ */

#if defined(__ia64__)

// On RHEL5 ia64, __NR_umount2 doesn't exist. So, define it in terms
// of __NR_umount.

#ifndef __NR_umount2
#define __NR_umount2 __NR_umount
#endif

#endif	/* __ia64__ */

#endif /* _COMPAT_UNISTD_H_ */
