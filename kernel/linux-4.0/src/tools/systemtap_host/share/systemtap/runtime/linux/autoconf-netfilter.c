#include <linux/netfilter.h>

unsigned int
new_style_hook(const struct nf_hook_ops *ops,  /* not: unsigned int hook; */
               struct sk_buff *skb,
               const struct net_device *in, const struct net_device *out,
               int (*okfn)(struct sk_buff *))
{
  (void) ops; (void) skb;  (void) in; (void) out; (void) okfn;
  return 0;
}

struct nf_hook_ops netfilter_ops = {
  .hook = new_style_hook
};

