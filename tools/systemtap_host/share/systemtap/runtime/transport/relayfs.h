#ifndef _TRANSPORT_RELAYFS_H_ /* -*- linux-c -*- */
#define _TRANSPORT_RELAYFS_H_

/** @file relayfs.h
 * @brief Header file for relayfs transport
 */

#if defined (CONFIG_RELAYFS_FS) || defined (CONFIG_RELAYFS_FS_MODULE)
#  include <linux/relayfs_fs.h>
#elif defined (CONFIG_RELAY)
#  include <linux/relay.h>
#else
#  undef STP_RELAYFS
#endif

#  include <linux/namei.h>

static struct rchan *_stp_relayfs_open(unsigned n_subbufs,
				unsigned subbuf_size,
				int pid,
				struct dentry **outdir);

static void _stp_relayfs_close(struct rchan *chan, struct dentry *dir);

#endif /* _TRANSPORT_RELAYFS_H_ */
