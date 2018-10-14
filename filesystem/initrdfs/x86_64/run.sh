#!/bin/bash
KERNEL_BUILD=/home/chengjian/Work/Kernel/RunningLinuxKernel/RunningLinuxKernel/kernel/linux-4.0/build/x86_64

qemu-system-x86_64						\
	-kernel ${KERNEL_BUILD}/arch/x86/boot/bzImage		\
	-append "root=/dev/ram rdinit=/linuxrc console=ttyS0"	\
	-initrd ./rootfs.cpio.gz				\
	-nographic

