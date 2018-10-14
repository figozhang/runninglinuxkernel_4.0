#include <linux/relay.h>

/* commit 4e6b225dab95a4d43b3e7bdc7e79cbca4c145596
 * Author: Al Viro <viro@zeniv.linux.org.uk>
 * Date:   Sun Jul 24 04:33:43 2011 -0400
 *
 *     switch debugfs to umode_t
 */


static struct dentry *
umode_t_callback(const char *filename,
                 struct dentry *parent,
                 umode_t mode, /* as opposed to mode_t=__kernel_mode_t */
                 struct rchan_buf *buf,
                 int *is_global)
{
  (void) filename;
  (void) parent;
  (void) mode;
  (void) buf;
  (void) is_global;
  return NULL;
}

static struct rchan_callbacks __stp_relay_callbacks = {
   .create_buf_file = umode_t_callback,
};

void foo (void) {
   (void) __stp_relay_callbacks.create_buf_file;
}

