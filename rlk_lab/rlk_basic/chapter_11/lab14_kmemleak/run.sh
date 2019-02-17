#!/bin/bash

LROOT=$PWD
ROOTFS_X86=_install_x86
ROOTFS_ARM32=_install_arm32
ROOTFS_ARM64=_install_arm64
CONSOLE_DEV_NODE=dev/console

if [ $# -lt 1 ]; then
	echo "Usage: $0 [arch] [debug]"
fi

if [ $# -eq 2 ] && [ $2 == "debug" ]; then
	echo "Enable GDB debug mode"
	DBG="-s -S"
fi

case $1 in
	x86_64)
		if [ ! -c $LROOT/$ROOTFS_X86/$CONSOLE_DEV_NODE ]; then
			echo "please create console device node first, and recompile kernel"
			exit 1
		fi
		qemu-system-x86_64 -kernel arch/x86/boot/bzImage \
				   -append "rdinit=/linuxrc console=ttyS0" -nographic \
				   --virtfs local,id=kmod_dev,path=$PWD/kmodules,security_model=none,mount_tag=kmod_mount \
				   $DBG ;;
	x86)
		if [ ! -c $LROOT/$ROOTFS_X86/$CONSOLE_DEV_NODE ]; then
			echo "please create console device node first, and recompile kernel"
			exit 1
		fi
		qemu-system-i386 -kernel arch/x86/boot/bzImage \
				 -append "rdinit=/linuxrc console=ttyS0" -nographic \
				 --virtfs local,id=kmod_dev,path=$PWD/kmodules,security_model=none,mount_tag=kmod_mount \
				 $DBG ;;
	arm32)
		if [ ! -c $LROOT/$ROOTFS_ARM32/$CONSOLE_DEV_NODE ]; then
			echo "please create console device node first, and recompile kernel"
			exit 1
		fi
		qemu-system-arm -M vexpress-a9 -smp 4 -m 100M -kernel arch/arm/boot/zImage \
				-dtb arch/arm/boot/dts/vexpress-v2p-ca9.dtb -nographic \
				-append "rdinit=/linuxrc console=ttyAMA0 loglevel=8 slub_debug kmemleak=on" \
				--fsdev local,id=kmod_dev,path=$PWD/kmodules,security_model=none -device virtio-9p-device,fsdev=kmod_dev,mount_tag=kmod_mount \
				$DBG ;;
	arm64)
		if [ ! -c $LROOT/$ROOTFS_ARM64/$CONSOLE_DEV_NODE ]; then
			echo "please create console device node first, and recompile kernel"
			exit 1
		fi
		qemu-system-aarch64 -machine virt -cpu cortex-a57 -machine type=virt \
				    -m 1024 -smp 2 -kernel arch/arm64/boot/Image \
				    --append "rdinit=/linuxrc console=ttyAMA0" -nographic \
				    --fsdev local,id=kmod_dev,path=$PWD/kmodules,security_model=none -device virtio-9p-device,fsdev=kmod_dev,mount_tag=kmod_mount \
				    $DBG ;;
esac
