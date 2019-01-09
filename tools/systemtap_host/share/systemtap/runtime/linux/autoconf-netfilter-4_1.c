#include <linux/netfilter.h>

// The following kernel commit first appears in v4.1-rc1 and modifies
// the netfilter hook function signature (again).
//
//   commit 238e54c9cb9385a1ba99e92801f3615a2fb398b6
//   Author: David S. Miller <davem@davemloft.net>
//   Date:   Fri Apr 3 20:32:56 2015 -0400
//   
//   netfilter: Make nf_hookfn use nf_hook_state.
//   
//       Pass the nf_hook_state all the way down into the hook
//       functions themselves.
//   
//   Signed-off-by: David S. Miller <davem@davemloft.net>

unsigned int
newer_style_hook(const struct nf_hook_ops *ops,
		 struct sk_buff *skb,
		 const struct nf_hook_state *state)
{
  (void) ops; (void) skb; (void) state;
  return 0;
}

struct nf_hook_ops netfilter_ops = {
  .hook = newer_style_hook
};

