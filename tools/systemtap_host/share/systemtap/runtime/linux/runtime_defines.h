// The following kernel commit renamed __GFP_WAIT to __GRP_RECLAIM:
//
//   commit 71baba4b92dc1fa1bc461742c6ab1942ec6034e9
//   Author: Mel Gorman <mgorman@techsingularity.net>
//   Date:   Fri Nov 6 16:28:28 2015 -0800
// 
//       mm, page_alloc: rename __GFP_WAIT to __GFP_RECLAIM
//     
//       __GFP_WAIT was used to signal that the caller was in atomic
//       context and could not sleep.  Now it is possible to
//       distinguish between true atomic context and callers that are
//       not willing to sleep.  The latter should clear
//       __GFP_DIRECT_RECLAIM so kswapd will still wake.  As clearing
//       __GFP_WAIT behaves differently, there is a risk that people
//       will clear the wrong flags.  This patch renames __GFP_WAIT to
//       __GFP_RECLAIM to clearly indicate what it does -- setting it
//       allows all reclaim activity, clearing them prevents it.
//
// Handle the rename by defining __GFP_WAIT as __GFP_RECLAIM.
#include <linux/gfp.h>
#ifndef __GFP_WAIT
#define __GFP_WAIT __GFP_RECLAIM
#endif
