
LROOT=$PWD
JOBCOUNT=${JOBCOUNT=$(nproc)}
ROOTFS_ARM64=_install_arm64
CONSOLE_DEV_NODE=dev/console

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-

if [ ! -c $LROOT/$ROOTFS_ARM64/$CONSOLE_DEV_NODE ]; then
	echo "Canot find device node on $ROOTFS_ARM64/$CONSOLE_DEV_NODE !!"
	echo "Please create console device node first, and try again!"
	echo "#sudo mknod $ROOTFS_ARM64/$CONSOLE_DEV_NODE c 5 1"
	exit 1
fi

echo "start build kernel image..."
make defconfig
make -j $JOBCOUNT

cd boot-wrapper-aarch64
autoreconf -i
./configure --enable-psci --enable-gicv3 --with-kernel-dir=$LROOT --with-dtb=fvp-base-gicv3-psci.dtb --host=aarch64-linux-gnu --with-cmdline="rdinit=/linuxrc console=ttyAMA0"

make
