#ifdef CONFIG_COMPAT

/*
 * 'struct compat_sigaction' added by:
 *
 *   commit 574c4866e33d648520a8bd5bf6f573ea6e554e88
 *   Author: Al Viro <viro@zeniv.linux.org.uk>
 *   Date:   Sun Nov 25 22:24:19 2012 -0500
 *   
 *       consolidate kernel-side struct sigaction declarations
 *       
 *       Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
 */

#include <linux/compat.h>

struct compat_sigaction cs;

#else
#error "no CONFIG_COMPAT"
#endif
