#!/bin/bash

LROOT=$PWD
JOBCOUNT=${JOBCOUNT=$(nproc)}
export ARCH=x86_64
export INSTALL_PATH=$LROOT/rootfs_debian_x86_64/boot/
export INSTALL_MOD_PATH=$LROOT/rootfs_debian_x86_64/
export INSTALL_HDR_PATH=$LROOT/rootfs_debian_x86_64/usr/

kernel_build=$PWD/rootfs_debian_x86_64/usr/src/linux/
rootfs_path=$PWD/rootfs_debian_x86_64
rootfs_image=$PWD/rootfs_debian_x86_64.ext4

rootfs_size=8192

SMP="-smp 4"

if [ $# -lt 1 ]; then
	echo "Usage: $0 [arg]"
	echo "build_kernel: build the kernel image."
	echo "build_rootfs: build the rootfs image."
	echo " run:  run debian system."
fi

if [ $# -eq 2 ] && [ $2 == "debug" ]; then
	echo "Enable qemu debug server"
	DBG="-s -S"
	SMP=""
fi

make_kernel_image(){
		echo "start build kernel image..."
		make debian_defconfig
		make -j $JOBCOUNT
}

prepare_rootfs(){
		if [ ! -d $rootfs_path ]; then
			echo "decompressing rootfs..."
			tar -Jxf rootfs_debian_x86_64.tar.xz
		fi
}

build_kernel_devel(){
	kernver="$(make -s kernelrelease)"
	echo "kernel version: $kernver"

	mkdir -p $kernel_build
	rm rootfs_debian_x86_64/lib/modules/$kernver/build
	cp -a include $kernel_build
	cp Makefile .config Module.symvers System.map $kernel_build
	mkdir -p $kernel_build/arch/x86/
	mkdir -p $kernel_build/arch/x86/kernel/
	mkdir -p $kernel_build/scripts

	cp -a arch/x86/include $kernel_build/arch/x86/
	cp -a arch/x86/Makefile $kernel_build/arch/x86/
	cp scripts/gcc-goto.sh $kernel_build/scripts
	cp -a scripts/Makefile.*  $kernel_build/scripts
	#cp arch/x86/kernel/module.lds $kernel_build/arch/x86/kernel/

	ln -s /usr/src/linux rootfs_debian_x86_64/lib/modules/$kernver/build

}

check_root(){
		if [ "$(id -u)" != "0" ];then
			echo "superuser privileges are required to run"
			echo "sudo ./run_debian_x86_64.sh build_rootfs"
			exit 1
		fi
}

build_rootfs(){
		if [ ! -f $rootfs_image ]; then
			make install
			make modules_install -j $JOBCOUNT
			#make headers_install

			build_kernel_devel

			echo "making image..."
			dd if=/dev/zero of=rootfs_debian_x86_64.ext4 bs=1M count=$rootfs_size
			mkfs.ext4 rootfs_debian_x86_64.ext4
			mkdir -p tmpfs
			echo "copy data into rootfs..."
			mount -t ext4 rootfs_debian_x86_64.ext4 tmpfs/ -o loop
			cp -af rootfs_debian_x86_64/* tmpfs/
			umount tmpfs
			chmod 777 rootfs_debian_x86_64.ext4
		fi

}

run_qemu_debian(){
		qemu-system-x86_64 -m 1024\
			-nographic $SMP -kernel arch/x86/boot/bzImage \
			-append "noinintrd console=ttyS0 crashkernel=256M root=/dev/vda rootfstype=ext4 rw loglevel=8" \
			-drive if=none,file=rootfs_debian_x86_64.ext4,id=hd0 \
			-device virtio-blk-pci,drive=hd0 \
			-netdev user,id=mynet\
			-device virtio-net-pci,netdev=mynet\
			--fsdev local,id=kmod_dev,path=./kmodules,security_model=none \
			-device virtio-9p-pci,fsdev=kmod_dev,mount_tag=kmod_mount\
			$DBG

}

case $1 in
	build_kernel)
		make_kernel_image
		#prepare_rootfs
		#build_rootfs
		;;
	
	build_rootfs)
		#make_kernel_image
		check_root
		prepare_rootfs
		build_rootfs
		;;
	run)

		if [ ! -f $LROOT/arch/x86/boot/bzImage ]; then
			echo "canot find kernel image, pls run build_kernel command firstly!!"
			echo "./run_debian_x86_64.sh build_kernel"
			exit 1
		fi

		if [ ! -f $rootfs_image ]; then
			echo "canot find rootfs image, pls run build_rootfs command firstly!!"
			echo "sudo ./run_debian_x86_64.sh build_rootfs"
			exit 1
		fi

		#prepare_rootfs
		#build_rootfs
		run_qemu_debian
		;;
esac

