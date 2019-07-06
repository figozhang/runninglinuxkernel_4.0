
# 说明

该实验为《奔跑吧Linux入门版》中第六章的实验2的参考代码。

实验要求添加的系统调用不传递任何参数，一般将`pid`和`uid`直接通过`printk`输出到`dmesg`中，但是这样非常的不优雅。该参考代码添加了一个系统调用

```c
long getpuid(pid_t *pid, uid_t *uid);
```

`pid`和`uid`通过参数返回。

为了方便进行实验，以下实验基于《奔跑吧Linux入门版》中第一章的实验室2，我们选定了最新的社区稳定版内核来修改添加系统调用，然后编译后，安装到优麒麟Linux机器上。

# 实验步骤

## 下载最新的社区稳定版内核

在完成该实验时，社区最新的稳定版内核是`linux-5.1.16`，下载方法如下：
```
$ wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.1.16.tar.xz
$ xz -d linux-5.1.16.tar.xz 
$ tar -xf linux-5.1.16.tar 
$ cd linux-5.1.16/
```


## 添加系统调用getpuid

`0001-x86-add-a-new-syscall-which-called-getpuid.patch`是基于`linux-5.1.16`制作的patch，如果是其它版本，请参考如下该`patch`进行修改：

```
$ cat 0001-x86-add-a-new-syscall-which-called-getpuid.patch 
From e4d3eb5953e8933cad1b51915c917dd7905d7078 Mon Sep 17 00:00:00 2001
From: Wang Long <w@laoqinren.net>
Date: Sat, 6 Jul 2019 10:06:03 +0800
Subject: [PATCH] x86: add a new syscall which called getpuid

This patch add a new syscall for x86, which name is getpuid.
getpuid return the current process's pid and uid.

its prototype is: long sys_getpuid(pid_t *pid, uid_t *uid);

Signed-off-by: Wang Long <w@laoqinren.net>
---
 arch/x86/entry/syscalls/syscall_64.tbl |  1 +
 include/linux/syscalls.h               |  1 +
 kernel/sys.c                           | 14 ++++++++++++++
 3 files changed, 16 insertions(+)

diff --git a/arch/x86/entry/syscalls/syscall_64.tbl b/arch/x86/entry/syscalls/syscall_64.tbl
index 92ee0b437..f8afc50c9 100644
--- a/arch/x86/entry/syscalls/syscall_64.tbl
+++ b/arch/x86/entry/syscalls/syscall_64.tbl
@@ -343,6 +343,7 @@
 332	common	statx			__x64_sys_statx
 333	common	io_pgetevents		__x64_sys_io_pgetevents
 334	common	rseq			__x64_sys_rseq
+350	common	getpuid			__x64_sys_getpuid
 # don't use numbers 387 through 423, add new calls after the last
 # 'common' entry
 424	common	pidfd_send_signal	__x64_sys_pidfd_send_signal
diff --git a/include/linux/syscalls.h b/include/linux/syscalls.h
index e446806a5..8f007f00b 100644
--- a/include/linux/syscalls.h
+++ b/include/linux/syscalls.h
@@ -1390,4 +1390,5 @@ static inline unsigned int ksys_personality(unsigned int personality)
 	return old;
 }
 
+asmlinkage long sys_getpuid(pid_t __user *pid, uid_t __user *uid);
 #endif
diff --git a/kernel/sys.c b/kernel/sys.c
index bdbfe8d37..d75d8654d 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -2648,4 +2648,18 @@ COMPAT_SYSCALL_DEFINE1(sysinfo, struct compat_sysinfo __user *, info)
 
 	return 0;
 }
+
+SYSCALL_DEFINE2(getpuid, pid_t __user *, pid, uid_t __user *, uid) {
+       if (pid == NULL && uid == NULL)
+               return -EINVAL;
+
+       if (pid != NULL)
+               *pid = task_tgid_vnr(current);
+
+       if (uid != NULL)
+               *uid = from_kuid_munged(current_user_ns(), current_uid());
+
+       return 0;
+}
+
 #endif /* CONFIG_COMPAT */
-- 
2.17.1
```

## 编译

为了方便，我们直接复制优麒麟Linux系统中自带的配置文件，我的系统上的配置文件为：`/boot/config-4.18.0-16-generic`，相关命令如下：

```
$ cd linux-5.1.16/
$ cp /boot/config-4.18.0-16-generic .config
$ make menuconfig
$ make -j4
```

## 安装
```
$ sudo make modules_install
$ sudo make install
```

安装完成后，重启电脑，用刚才编译的内核启动，登录系统。

## 编写应用程序并编译运行

```
$ cd ~/runninglinuxkernel_4.0
$ cd rlk_lab/rlk_basic/chapter_6/lab2/
$ gcc -o test_getpuid_syscall test_getpuid_syscall.c 
$ ./test_getpuid_syscall 
call getpuid success, return pid = 1419, uid = 1000
$ ./test_getpuid_syscall 
call getpuid success, return pid = 1420, uid = 1000
```
