#!/bin/bash

qemu-system-aarch64 -machine virt -cpu cortex-a57 -machine type=virt -nographic \
	-m 2018 -smp 2 -kernel /home/chengjian/Work/Kernel/RunningLinuxKernel/RunningLinuxKernel/kernel/linux-build/build/arm64/arch/arm64/boot/Image \
	--append "root/dev/ram rdinit=/linuxrc console=ttyAMA0"	\
	-initrd ./rootfs.cpio.gz
