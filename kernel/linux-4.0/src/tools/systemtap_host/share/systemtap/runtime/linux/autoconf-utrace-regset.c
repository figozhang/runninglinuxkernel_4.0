#include <linux/tracehook.h>

/* old rhel5 utrace regset */
int foobar(int n) { 
  const struct utrace_regset_view *rsv = utrace_native_view(current);  
  const struct utrace_regset *rs = & rsv->regsets[0];
  return rsv->n + n + (rs->get)(current, rs, 0, 0, NULL, NULL);
}
