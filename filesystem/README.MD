#1	CONFIG_INITRAMFS_SOURCE存在的问题
-------

之前我们的内核使用 initramfs 的时候, 是直接编译到内核里面的.
这就需要编译内核时需指定 `initramfs source file`

即配置 `CONFIG_INITRAMFS_SOURCE` 指向了我们制作好的 `RAMFS` 目录 `_install_ARCH`

```cpp
arch/arm64/configs/defconfig:CONFIG_INITRAMFS_SOURCE="_install_arm64"
arch/arm/configs/vexpress_defconfig:CONFIG_INITRAMFS_SOURCE="_install_arm32"
arch/x86/configs/x86_64_defconfig:CONFIG_INITRAMFS_SOURCE="_install_x86_64"
arch/x86/configs/i386_defconfig:CONFIG_INITRAMFS_SOURCE="_install_x86"
```

`CONFIG_INITRAMFS_SOURCE` 可以是一个绝对路径,
也可以是一个从 `kernel's top build dir` (你敲入 `build` 或者是 `make` 的地方)开始的相对路径.

而指向的目标可以有以下三种：

1.	一个已经做好的cpio.gz

2.	一个已经为制作cpio.gz准备好所有内容的文件夹

3.	或者是一个text的配置文件


之前的版本我们使用了第二种方式(指定了相对于  `kernel's top build dir` 的相对目录),
但是这里有个不好的地方在于.
如果我们内核是在其他路径下构建的, 那么相对路径就是错误的.
比如我们很有可能想要同时构建出多个 arch 的镜像, 
或者我们仅仅是想在另外的目录下构建内核, 从而不把内核源代码目录弄脏.
这时候我们经常使用 make defconfig O=kernel_build_dir 的来创建构建工作区.

比如 

*	ARM

```cpp
export ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-
make vexpress_defconfig O=../build/arm
```

此时运行脚本使用

```cpp
sh run.sh arm ../build/arm 
```

*	ARM64

```
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
make defconfig O=../build/arm64
```

*	X86

```
export ARCH=x86 CROSS_COMPILE= 
make defconfig O=../build/x86
```

*	X86_64

```
export ARCH=x86_64 CROSS_COMPILE= 
make defconfig O=../build/x86_64
```

这样我们只需要在 ../build/arch 下的目录下, 进行 `make` 就可以了.
我们的内核源代码还是干净的, 多个架构下的工作也互不干扰.

但是如果使用 `CONFIG_INITRAMFS_SOURCE`, 每次需要修改 config 文件修改 ramfs 文件系统的路径.
又很是麻烦, 有没有什么方法可以解决这个问题呢?


#2	qemu initrd 加载文件系统
-------

那肯定是有的, `qemu` 本身就支持直接指定 `initrd` 文件

##2.1	制作 initramfs 文件系统镜像
-------

```cpp
Linux/Multiboot boot specific:
-kernel bzImage use 'bzImage' as kernel image
-append cmdline use 'cmdline' as kernel command line
-initrd file    use 'file' as initial ram disk
-dtb    file    use 'file' as device tree image
```

因此我们提供了 `./initrdfs/build-initrdfs.sh` 将之前的文件制作成 `cpio` 镜像.

`./initrdfs` 目录下对应 arch 下面有已经制作好的 cpio 镜像.
你也可以自行制作.

```cpp
cd initrdfs
bash ./build-initrdfs.sh arch
```

##2.2	qemu 加载 initramfs 文件系统
-------

`append` 在系统参数中添加 `root=/dev/ram`
`initrd` 中指定对应的文件系统即可.

```cpp
-append "root=/dev/ram rdinit=/linuxrc console=ttyAMA0 loglevel=8"
-initrd ./rootfs.cpio.gz
```

##2.3	run.sh 使用
-------


```cpp
sh run.sh arch kernel_top_build_dir
```
