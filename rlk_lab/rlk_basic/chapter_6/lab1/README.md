# 说明

该实验为《奔跑吧Linux入门版》中第六章的实验1的参考代码。

实验要求添加的系统调用不传递任何参数，一般将`pid`和`uid`直接通过`printk`输出到`dmesg`中，但是这样非常的不优雅。该参考代码添加了一个系统调用

```c
long getpuid(pid_t *pid, uid_t *uid);
```

`pid`和`uid`通过参数返回。


# 实验步骤

## 添加patch

```
# cd ~/runninglinuxkernel_4.0
# git am rlk_lab/rlk_basic/chapter_6/lab1/0001-arm32-add-a-new-syscall-which-called-getpuid.patch
```
* 这里我们新添加的系统调用名称为`getpuid`
* `getpuid`使用的系统调用号为`388`

## 编译内核

如何编译内核，详细可以参考《奔跑吧Linux入门版》中第一章的实验室3。

```
# export ARCH=arm
# export CROSS_COMPILE=arm-linux-gnueabi-
# make vexpress_defconfig
# make menuconfig
# make bzImage -j4
# make dtbs
```

## 编写应用程序并编译

```
# cp rlk_lab/rlk_basic/chapter_6/lab1/test_getpuid_syscall.c kmodules/test_getpuid_syscall.c
# cd kmodules/
# arm-linux-gnueabi-gcc --static -o test_getpuid_syscall test_getpuid_syscall.c 
# cd ..
```

## 启动内核

```
# ./run.sh arm32
```

## 编写并运行应用程序

```
# cd /mnt
/mnt # ./test_getpuid_syscall
call getpuid success, return pid = 809, uid = 0
/mnt # ./test_getpuid_syscall
call getpuid success, return pid = 810, uid = 0
/mnt # 
```
