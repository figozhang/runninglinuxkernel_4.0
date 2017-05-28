#ifndef _PTRACE_COMPATIBILITY_H_
#define _PTRACE_COMPATIBILITY_H_

#include <linux/ptrace.h>

/* Older kernel's linux/ptrace.h don't define
 * arch_has_single_step()/arch_has_block_step(). */

#ifndef arch_has_single_step

#include <linux/tracehook.h>

/**
 * arch_has_single_step - does this CPU support user-mode single-step?
 *
 * If this is defined, then there must be function declarations or
 * inlines for user_enable_single_step() and user_disable_single_step().
 * arch_has_single_step() should evaluate to nonzero iff the machine
 * supports instruction single-step for user mode.
 * It can be a constant or it can test a CPU feature bit.
 */

#ifdef ARCH_HAS_SINGLE_STEP
#define arch_has_single_step()	(ARCH_HAS_SINGLE_STEP)
#else
#define arch_has_single_step()	(0)
#endif	/* ARCH_HAS_SINGLE_STEP */

#endif	/* arch_has_single_step */

#ifndef arch_has_block_step
/**
 * arch_has_block_step - does this CPU support user-mode block-step?
 *
 * If this is defined, then there must be a function declaration or inline
 * for user_enable_block_step(), and arch_has_single_step() must be defined
 * too.  arch_has_block_step() should evaluate to nonzero iff the machine
 * supports step-until-branch for user mode.  It can be a constant or it
 * can test a CPU feature bit.
 */

#ifdef ARCH_HAS_BLOCK_STEP
#define arch_has_block_step()	(ARCH_HAS_BLOCK_STEP)
#else
#define arch_has_block_step()   (0)
#endif	/* ARCH_HAS_BLOCK_STEP */

#endif	/* arch_has_block_step */

#endif	/* _PTRACE_COMPATIBILITY_H_ */
