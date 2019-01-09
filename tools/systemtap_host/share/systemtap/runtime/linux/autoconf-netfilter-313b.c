#include <linux/netfilter.h>

// Similarly to autoconf-netfilter-4_1.c, this autoconf test covers
// backport of kernel patch 238e54c9cb9385a1ba99e92801f3615a2fb398b6
// to kernel-3.10.0-284.el7 per rhbz1230935#c4 as patch no 119478.
// This fixes PR18711.

unsigned int
new_style_hook(const struct nf_hook_ops *ops,
		 struct sk_buff *skb,
		 const struct net_device *nf_in,
		 const struct net_device *nf_out,
		 const struct nf_hook_state *state)
{
  (void) ops; (void) skb; (void) nf_in; (void) nf_out; (void) state;
  return 0;
}

struct nf_hook_ops netfilter_ops = {
  .hook = new_style_hook
};

