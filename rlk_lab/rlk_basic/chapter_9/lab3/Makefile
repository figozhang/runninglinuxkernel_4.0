
BASEINCLUDE ?= /home/figo/work/runninglinuxkernel/runninglinuxkernel_4.0
ccflags-y :=-g

rcu-objs := rcu_test.o 

obj-m	:=   rcu.o
all : 
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) modules;

clean:
	$(MAKE) -C $(BASEINCLUDE) SUBDIRS=$(PWD) clean;
	rm -f *.ko;


