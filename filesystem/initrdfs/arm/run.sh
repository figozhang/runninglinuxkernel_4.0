#!/bin/bash

KERNEL_BUILD=/home/chengjian/Work/Kernel/RunningLinuxKernel/RunningLinuxKernel/kernel/linux-build/build/arm

qemu-system-arm -M vexpress-a9 -smp 4 -m 1024M					\
	-kernel ${KERNEL_BUILD}/arch/arm/boot/zImage			\
	-dtb ${KERNEL_BUILD}/arch/arm/boot/dts/vexpress-v2p-ca9.dtb		\
	-append "root=/dev/ram rdinit=/linuxrc console=ttyAMA0 loglevel=8"	\
	-initrd ./rootfs.cpio.gz						\
	-nographic
