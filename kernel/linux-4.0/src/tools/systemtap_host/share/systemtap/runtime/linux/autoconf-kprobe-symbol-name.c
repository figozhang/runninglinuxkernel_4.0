#include <linux/kprobes.h>

void func(struct kprobe *kp)
{
  kp->symbol_name = "dummy";
}
