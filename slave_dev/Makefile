obj-m := slave.o
slave-y := slave_dev.o
ccflags-y := -I$(PWD)/../ksocket/src -g

PWD := $(shell pwd)
KDIR := $(shell uname -r)

all:
	ln -sf ../ksocket/src/Module.symvers .
	make -C /lib/modules/$(KDIR)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KDIR)/build M=$(PWD) clean
