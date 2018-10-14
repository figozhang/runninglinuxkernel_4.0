/* Common runtime defines, not dependend on session variables.
   Included once at the top of the generated stap.c file by the translate.cxx
   translate_pass ().  */


#if defined(__KERNEL__)

#include "linux/runtime_defines.h"

#elif defined(__DYNINST__)

#include "dyninst/runtime_defines.h"

#endif


/* Strings are used for storing backtraces, they are larger on 64bit
   so raise the size on 64bit architectures. PR10486.  */
#include <asm/types.h>
#ifndef MAXSTRINGLEN
#if BITS_PER_LONG == 32
#define MAXSTRINGLEN 256
#else
#define MAXSTRINGLEN 512
#endif
#endif
typedef char string_t[MAXSTRINGLEN];

#if !defined(STAP_SUPPRESS_TIME_LIMITS_ENABLE)
#ifndef MAXACTION
#define MAXACTION 1000
#endif
#ifndef MAXACTION_INTERRUPTIBLE
#define MAXACTION_INTERRUPTIBLE (MAXACTION * 10)
#endif
#endif
#ifndef TRYLOCKDELAY
#define TRYLOCKDELAY 10 /* microseconds */
#endif
#ifndef MAXTRYLOCK
#define MAXTRYLOCK 100 /* 1 millisecond total */
#endif
#ifndef MAXMAPENTRIES
#define MAXMAPENTRIES 2048
#endif
#ifndef MAXERRORS
#define MAXERRORS 0
#endif
#ifndef MAXSKIPPED
#define MAXSKIPPED 100
#endif
#ifndef MINSTACKSPACE
#define MINSTACKSPACE 1024
#endif
#ifndef INTERRUPTIBLE
#define INTERRUPTIBLE 1
#endif

/* Overload processing.  */
#ifndef STP_OVERLOAD_INTERVAL
#define STP_OVERLOAD_INTERVAL 1000000000LL
#endif
#ifndef STP_OVERLOAD_THRESHOLD
#define STP_OVERLOAD_THRESHOLD 500000000LL
#endif

/* We allow the user to completely turn overload processing off
   (as opposed to tuning it by overriding the values above) by
   running:  stap -DSTP_NO_OVERLOAD {other options}.  */
#if !defined(STP_NO_OVERLOAD) && !defined(STAP_NO_OVERLOAD) && !defined(STAP_SUPPRESS_TIME_LIMITS_ENABLE)
#define STP_OVERLOAD
#endif

/* Used for CONTEXT probe_type. */
enum stp_probe_type {
/* begin, end or never probe, triggered by stap module itself. */
	stp_probe_type_been,
/* user space instruction probe, trigger by utrace signal report. */
	stp_probe_type_itrace,
/* kernel marker probe, triggered by old marker_probe (removed in 2.6.32). */
	stp_probe_type_marker,
/* perf event probe, triggered by perf event counter.
   Note that although this is defined in tapset-perfmon.cxx, this has
   nothing to do with the (old and now removed) perfmon probes. */
	stp_probe_type_perf,
/* read or write of stap module proc file. Triggers on manipulation of
   the /proc/systemtap/MODNAME created through a procfs probe. */
	stp_probe_type_procfs,
/* timer probe, triggered by standard kernel init_timer interface. */
	stp_probe_type_timer,
/* high resolution timer probes, triggered by hrtimer firing. */
	stp_probe_type_hrtimer,
/* profile timer probe, triggered by kernel profile timer (either in
   kernel or user space). */
	stp_probe_type_profile_timer,
/* utrace thread start/end probe, triggered by utrace quiesce event for
   associated thread. */
	stp_probe_type_utrace,
/* utrace syscall enter/exit probe, triggered by utrace syscall event. */
	stp_probe_type_utrace_syscall,
/* kprobe event, triggered for dwarf or dwarfless kprobes. */
	stp_probe_type_kprobe,
/* kretprobe event, triggered for dwarf or dwarfless kretprobes. */
	stp_probe_type_kretprobe,
/* uprobe event, triggered by hitting a uprobe. */
	stp_probe_type_uprobe,
/* uretprobe event, triggered by hitting a uretprobe. */
	stp_probe_type_uretprobe,
/* hardware data watch break point, triggered by kernel data read/write. */
	stp_probe_type_hwbkpt,
/* kernel tracepoint probe, triggered by tracepoint event call. */
	stp_probe_type_tracepoint,
/* netfilter probe, triggered on network trafic */
	stp_probe_type_netfilter,
};
