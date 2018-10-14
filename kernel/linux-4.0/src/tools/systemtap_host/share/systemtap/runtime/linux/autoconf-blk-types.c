/* 
 * Make sure linux/blk_types.h exists and is usable.
 *
 * PR18944: On RHEL7, linux/blk_types.h was missing inclusion of
 * linux/rh_kabi.h, so include linux/blkdev.h which will hopefully
 * include linux/rh_kabi.h (which we can't include directly since it
 * doesn't exist on non-RHEL kernels).
 */
#include <linux/blkdev.h>
#include <linux/blk_types.h>
