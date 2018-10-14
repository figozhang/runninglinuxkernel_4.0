/*
 * Architecture specific compatibility type for various structs. In older
 * kernels, these weren't in public headers.
 */

#ifndef _COMPAT_STRUCTS_H_
#define _COMPAT_STRUCTS_H_

#if defined(__powerpc64__)
typedef struct sigaltstack_32 {
    unsigned int ss_sp;
    int ss_flags;
    compat_size_t ss_size;
} stack_32_t;

#ifndef SI_PAD_SIZE32
#define SI_PAD_SIZE32	(128/sizeof(int) - 3)
#endif

typedef struct compat_siginfo {
	int si_signo;
	int si_errno;
	int si_code;

	union {
		int _pad[SI_PAD_SIZE32];

		/* kill() */
		struct {
			compat_pid_t _pid;		/* sender's pid */
			__compat_uid_t _uid;		/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			compat_timer_t _tid;		/* timer id */
			int _overrun;			/* overrun count */
			compat_sigval_t _sigval;	/* same as below */
			int _sys_private;	/* not to be passed to user */
		} _timer;

		/* POSIX.1b signals */
		struct {
			compat_pid_t _pid;		/* sender's pid */
			__compat_uid_t _uid;		/* sender's uid */
			compat_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			compat_pid_t _pid;		/* which child */
			__compat_uid_t _uid;		/* sender's uid */
			int _status;			/* exit code */
			compat_clock_t _utime;
			compat_clock_t _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGEMT */
		struct {
			unsigned int _addr; /* faulting insn/memory ref. */
		} _sigfault;

		/* SIGPOLL */
		struct {
			int _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;
	} _sifields;
} compat_siginfo_t;
#endif /* __powerpc64__ */

#if defined(__s390x__)
typedef struct {
    __u32                   ss_sp;          /* pointer */
    int                     ss_flags;
    compat_size_t           ss_size;
} stack_t32;

typedef struct compat_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;

	union {
		int _pad[128/sizeof(int) - 3];

		/* kill() */
		struct {
			pid_t	_pid;	/* sender's pid */
			uid_t	_uid;	/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			compat_timer_t _tid;		/* timer id */
			int _overrun;			/* overrun count */
			compat_sigval_t _sigval;	/* same as below */
			int _sys_private;	/* not to be passed to user */
		} _timer;

		/* POSIX.1b signals */
		struct {
			pid_t			_pid;	/* sender's pid */
			uid_t			_uid;	/* sender's uid */
			compat_sigval_t		_sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			pid_t			_pid;	/* which child */
			uid_t			_uid;	/* sender's uid */
			int			_status;/* exit code */
			compat_clock_t		_utime;
			compat_clock_t		_stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
		struct {
			__u32	_addr;	/* faulting insn/memory ref. - pointer */
		} _sigfault;

		/* SIGPOLL */
		struct {
			int	_band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int	_fd;
		} _sigpoll;
	} _sifields;
} compat_siginfo_t;
#endif /* __s390x__ */

#if defined(__x86_64__)
// x86_64 has an accessible header.
#include <asm/ia32.h>
#endif /* __x86_64__ */

#if defined(__aarch64__)
typedef struct compat_siginfo {
	int si_signo;
	int si_errno;
	int si_code;

	union {
		/* The padding is the same size as AArch64. */
		int _pad[128/sizeof(int) - 3];

		/* kill() */
		struct {
			compat_pid_t _pid;	/* sender's pid */
			__compat_uid32_t _uid;	/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			compat_timer_t _tid;	/* timer id */
			int _overrun;		/* overrun count */
			compat_sigval_t _sigval;	/* same as below */
			int _sys_private;       /* not to be passed to user */
		} _timer;

		/* POSIX.1b signals */
		struct {
			compat_pid_t _pid;	/* sender's pid */
			__compat_uid32_t _uid;	/* sender's uid */
			compat_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			compat_pid_t _pid;	/* which child */
			__compat_uid32_t _uid;	/* sender's uid */
			int _status;		/* exit code */
			compat_clock_t _utime;
			compat_clock_t _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS */
		struct {
			compat_uptr_t _addr; /* faulting insn/memory ref. */
			short _addr_lsb; /* LSB of the reported address */
		} _sigfault;

		/* SIGPOLL */
		struct {
			compat_long_t _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;

		/* SIGSYS */
		struct {
			compat_uptr_t _call_addr; /* calling user insn */
			int _syscall;	/* triggering system call number */
			compat_uint_t _arch;	/* AUDIT_ARCH_* of syscall */
		} _sigsys;
	} _sifields;
} compat_siginfo_t;
#endif /* __aarch64__ */

#endif /* _COMPAT_STRUCTS_H_ */
