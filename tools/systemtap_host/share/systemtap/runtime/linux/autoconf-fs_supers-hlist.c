#include <linux/fs.h>
#include <linux/list.h>

/*
commit 9591718a5a7da79f18eb01e626c77247993cdb61
Author: Al Viro <viro@zeniv.linux.org.uk>
Date:   Mon Dec 12 22:53:00 2011 -0500

vfs: convert fs_supers to hlist
    
Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
*/

int foo (struct super_block *sb) {
  return (hlist_unhashed (& sb->s_instances));
}
