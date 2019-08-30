## 说明

该实验为《奔跑吧Linux入门版》中第二章的实验2的参考代码。

## 移植步骤

1. 拷贝`runninglinuxkernel_4.0/include/linux/list.h`到`list.h`。
2. 删除掉`list.h`文件中`HLISH`相关的定义和宏。
3. 删除掉`list.h`文件中所有的头文件引用代码。
4. 在`list.h`文件开始的部分添加如下代码：

```c
#define POISON_POINTER_DELTA  0xdead000000000000
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x200 + POISON_POINTER_DELTA)

struct list_head {
	struct list_head *next, *prev;
};

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
```

## 编译运行 on x86__64 

$  make
$ ./main

##run on ARM32
$ arm-linux-gnueabi-gcc main.c -o main --static
$ cp main /home/figo/work/runninglinuxkernel_4.0/kmodues/
$ sh run.sh arm32

on Qemu:
$ cd /mnt
$ ./main
