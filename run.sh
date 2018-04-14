#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 [arch] [debug]"
fi

if [ $# -eq 2 ] && [ $2 == "debug" ]; then
    echo "Enable GDB debug mode"
    DBG="-s -S"
fi

case $1 in
    x86_64)
        qemu-system-x86_64 -kernel arch/x86/boot/bzImage \
                           -append "rdinit=/linuxrc console=ttyS0" -nographic \
                           --virtfs local,id=kmod_dev,path=$PWD/kmodules,security_model=none,mount_tag=kmod_mount \
                           -enable-kvm \
                           $DBG ;;
    x86)
        qemu-system-i386 -kernel arch/x86/boot/bzImage \
                           -append "rdinit=/linuxrc console=ttyS0" -nographic \
                           --virtfs local,id=kmod_dev,path=$PWD/kmodules,security_model=none,mount_tag=kmod_mount \
                           -enable-kvm \
                           $DBG ;;
    arm)
        qemu-system-arm -M vexpress-a9 -smp 4 -m 1024M -kernel arch/arm/boot/zImage \
                        -dtb arch/arm/boot/dts/vexpress-v2p-ca9.dtb -nographic \
                        -append "rdinit=/linuxrc console=ttyAMA0 loglevel=8" \
                        $DBG ;;
    arm64)
        qemu-system-aarch64 -machine virt -cpu cortex-a57 -machine type=virt \
                            -m 2048 –smp 2 -kernel arch/arm64/boot/Image \
                            --append "rdinit=/linuxrc console=ttyAMA0"-nographic \
                            $DBG ;;
esac
