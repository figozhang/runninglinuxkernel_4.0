#include <linux/kernel.h>
#include <linux/list.h>

struct foo {
        struct hlist_node foo_a;
};

struct hlist_head *h;

void foo (void)
{
        struct hlist_node *n;
        struct foo *fooptr;

        hlist_for_each_entry(fooptr, n, h, foo_a) {
                (void) fooptr;
        }
}
