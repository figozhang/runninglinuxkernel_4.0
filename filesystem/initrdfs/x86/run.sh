#!/bin/bash
KERNEL_BUILD=~/Work/Kernel/RunningLinuxKernel/RunningLinuxKernel/kernel/linux-build/build/x86

qemu-system-i386						\
	-kernel ${KERNEL_BUILD}/arch/x86/boot/bzImage		\
	-append "root=/dev/ram rdinit=/linuxrc console=ttyS0"	\
	-initrd ./rootfs.cpio.gz				\
	-nographic

