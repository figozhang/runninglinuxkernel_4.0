#!/bin/bash

#定义变量
ROOT_DIR=${PWD}/../..
ROOTFS_DIR=${ROOT_DIR}/filesystem
RAMFS_ROOTDIR=${ROOTFS_DIR}/rootfs
INITRDFS_ROOTDIR=${ROOTFS_DIR}/initrdfs

build_initrdfs()
{
	ARCH=$1
	RAMFS_DIR=${RAMFS_ROOTDIR}/_install_${ARCH}
	INITRDFS_DIR=${INITRDFS_ROOTDIR}/${ARCH}

	echo "====================="
	echo "orig	RAMFS : ${RAMFS_DIR}"
	echo "target INITRDFS : ${INITRDFS_DIR}/rootfs.cpio.gz"
	echo "====================="

	if [ ! -d $RAMFS_DIR ]; then
		echo "ramfs not exist, please check"
		exit 1
	fi
	if [ ! -c $LROOT/$ROOTFS_X86/$CONSOLE_DEV_NODE ]; then
		echo "please create console device node first, and recompile kernel"
		exit 1
	fi

	#通过cpio创建镜像
	cd ${RAMFS_DIR}
	#find . | cpio -o --format=newc > ${INITRDFS_DIR}/rootfs.cpio
	#gzip -c ${INITRDFS_DIR}/rootfs.cpio > ${INITRDFS_DIR}/rootfs.cpio.gz
	#通过gzip创建zip镜像
	find . | cpio -o --format=newc | gzip > ${INITRDFS_DIR}/rootfs.cpio.gz
}

if [ $# == 1 ];then
	build_initrdfs $1
else
	echo "$0 ARCH"
fi
