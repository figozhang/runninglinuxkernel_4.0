#include <linux/regset.h>

int foobar(int n) { 
  const struct user_regset_view *rsv = task_user_regset_view(current);  
  const struct user_regset *rs = & rsv->regsets[0];
  return rsv->n + n + (rs->get)(current, rs, 0, 0, NULL, NULL);
}
