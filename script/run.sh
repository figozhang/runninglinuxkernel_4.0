#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Usage: $0 [arch] [kernel_build_dir] [debug]"
	exit 1
fi

if [ $# -eq 3 ] && [ $3 == "debug" ]; then
	echo "Enable GDB debug mode"
	DBG="-s -S"
fi

LROOT=$PWD
ROOT_DIR=${PWD}/..
ARCH=$1
KERNEL_BUILD_DIR=$2


VIRFS=$ROOT_DIR/filesystem/9p_virtiofs
INITRDFS=$ROOT_DIR/filesystem/initrdfs/$ARCH/rootfs.cpio.gz

echo "====================="
echo "Kernel's Top Build Dir : " $KERNEL_BUILD_DIR
echo "InitRamFs : " $INITRDFS
echo "QEMU Share Folder : " $VIRFS
echo "====================="

if [ ! -d $KERNEL_BUILD_DIR ];then
	echo "ERROR kernel's top build dir $KERNEL_BUILD_DIR Not Found"
	echo "It's the place where your kernel build"
	echo "use the next to create it and build your kernel"
	echo "make xxx_defconfig O=$KERNEL_BUILD_DIR"
	exit 1
fi

if [ ! -f "$INITRDFS" ];then
	echo "ERROR initramfs $INITRDFS not found"
	echo ""
	exit 1
fi

case $ARCH in
	x86_64)
		KERNEL_IMAGE=$KERNEL_BUILD_DIR/arch/x86/boot/bzImage
		if [ ! -f $KERNEL_IMAGE ]; then
			echo "kernel image $KERNEL_IMAGE not found, please compile your kernel"
			exit 1
		fi
		qemu-system-x86_64 -kernel $KERNEL_IMAGE \
				   -append "root=/dev/ram rdinit=/linuxrc console=ttyS0" -nographic \
				   -initrd $INITRDFS	\
				   --virtfs local,id=kmod_dev,path=$VIRFS,security_model=none,mount_tag=kmod_mount \
				   $DBG ;;
	x86)
		KERNEL_IMAGE=$KERNEL_BUILD_DIR/arch/x86/boot/bzImage
		if [ ! -f $KERNEL_IMAGE ]; then
			echo "kernel image $KERNEL_IMAGE not found, please compile your kernel"
			exit 1
		fi
		qemu-system-i386 -kernel $KERNEL_IMAGE \
				 -append "/root=/dev/ram rdinit=/linuxrc console=ttyS0" -nographic \
				 -initrd $INITRDFS \
				 --virtfs local,id=kmod_dev,path=$VIRFS,security_model=none,mount_tag=kmod_mount \
				 $DBG ;;
	arm)
		KERNEL_IMAGE=$KERNEL_BUILD_DIR/arch/arm/boot/zImage
		if [ ! -f $KERNEL_IMAGE ]; then
			echo "kernel image $KERNEL_IMAGE not found, please compile your kernel"
			exit 1
		fi
		DTB_FILE=$KERNEL_BUILD_DIR/arch/arm/boot/dts/vexpress-v2p-ca9.dtb
		qemu-system-arm -M vexpress-a9 -smp 4 -m 1024M -kernel $KERNEL_IMAGE \
				-dtb $DTB_FILE -nographic \
				-append "root=/dev/ram rdinit=/linuxrc console=ttyAMA0 loglevel=8" \
				-initrd $INITRDFS \
				--fsdev local,id=kmod_dev,path=$VIRFS,security_model=none -device virtio-9p-device,fsdev=kmod_dev,mount_tag=kmod_mount \
				$DBG ;;
	arm64)
		KERNEL_IMAGE=$KERNEL_BUILD_DIR/arch/arm64/boot/Image
		if [ ! -f $KERNEL_IMAGE ]; then
			echo "kernel image $KERNEL_IMAGE not found, please compile your kernel"
			exit 1
		fi
		qemu-system-aarch64 -machine virt -cpu cortex-a57 -machine type=virt \
				    -m 1024 -smp 2 -kernel $KERNEL_IMAGE \
				    -append "root=/dev/ram rdinit=/linuxrc console=ttyAMA0" -nographic \
				    -initrd $INITRDFS \
				    --fsdev local,id=kmod_dev,path=$VIRFS,security_model=none -device virtio-9p-device,fsdev=kmod_dev,mount_tag=kmod_mount \
				    $DBG ;;
esac
