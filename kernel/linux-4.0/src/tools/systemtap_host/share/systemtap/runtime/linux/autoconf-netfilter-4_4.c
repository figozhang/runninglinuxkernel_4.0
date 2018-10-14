#include <linux/netfilter.h>

// The following kernel commit first appears in v4.4-rc1 and replaces
// the 'ops' paramter to netfilter function with 'priv':
//
//   commit 06198b34a3e09e06d9aecaa3727e0d37206cea77
//   Author: Eric W. Biederman <ebiederm@xmission.com>
//   Date:   Fri Sep 18 14:33:06 2015 -0500
//   
//   netfilter: Pass priv instead of nf_hook_ops to netfilter hooks
//   
//   Only pass the void *priv parameter out of the nf_hook_ops.  That is
//   all any of the functions are interested now, and by limiting what is
//   passed it becomes simpler to change implementation details.
//    
// The following kernel commit first appears in v4.4-rc1 and removes
// the 'owner' field from the nf_hook_ops structure.
//
//   commit 2ffbceb2b08f8ca0496c54a9ebcd11d25275954e
//   Author: Florian Westphal <fw@strlen.de>
//   Date:   Tue Oct 13 14:33:26 2015 +0200
//
//   netfilter: remove hook owner refcounting
//
//   since commit 8405a8fff3f8 ("netfilter: nf_qeueue: Drop queue entries on 
//   nf_unregister_hook") all pending queued entries are discarded.
//
//   So we can simply remove all of the owner handling -- when module is
//   removed it also needs to unregister all its hooks.

unsigned int even_newer_style_hook(void *priv,
				   struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
    (void) priv; (void) skb; (void) state;
    return 0;
}

struct nf_hook_ops netfilter_ops = {
  .hook = even_newer_style_hook
};
