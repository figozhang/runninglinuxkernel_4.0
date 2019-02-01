
# modify right kernel PATH for your system
BASEINCLUDE ?= /home/figo/work/runninglinuxkernel/runninglinuxkernel_4.0
#BASEINCLUDE ?= /lib/modules/`uname -r`/build

spinlock-test-objs := spinlock_test.o
spinlock-nest-objs := spinlock_nest.o

obj-m	:=   spinlock-test.o
obj-m	:=   spinlock-nest.o
all :
	$(MAKE) -C $(BASEINCLUDE) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


