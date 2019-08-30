## 说明

该实验为《奔跑吧Linux入门版》中第二章的实验3的参考代码。

## 移植步骤

1. 拷贝`runninglinuxkernel_4.0/include/linux/rbtree.h`到`rbtree.h`。
2. 拷贝`runninglinuxkernel_4.0/include/linux/rbtree_augmented.h`到`rbtree_augmented.h`。
3. 拷贝`runninglinuxkernel_4.0/lib/rbtree.c`到`rbtree.c`。
4. 删除`rbtree.c`文件中的`EXPORT_SYMBOL`代码行和`#include <linux/export.h>`引用。
5. 将`rbtree.c`文件中的`#include <linux/rbtree_augmented.h>`替换为`#include "rbtree_augmented.h"`。
6. 删除`rbtree.h`文件中引用的头文件，并在开始部分添加如下代码:

```c
#include <stdio.h>

#define NULL ((void *)0)
enum {
       false   = 0,
       true    = 1
};

#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
       const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
       (type *)( (char *)__mptr - offsetof(type,member) );})

```
7. 删除`rbtree_augmented.h`文件中引用的头文件，并添加引用`#include "rbtree.h"`。

## 编译运行 on x86__64
$  export CC=gcc
$  make
$ ./main

## 编译运行 on ARM32
$ export CC=arm-linux-gnueabi-gcc
$ make
$ cp main /home/rlk/rlk_basic/runninglinuxkernel/kmodules/

# run Qemu
$ sh run.sh arm32
$ cd /mnt
$ ./main
