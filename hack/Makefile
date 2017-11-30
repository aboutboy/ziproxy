ifeq ($(KERNELRELEASE),)
KERNELDIR :=  /usr/src/linux-headers-3.2.0-63-generic/
PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE)	-C $(KERNELDIR) M=$(PWD) modules_install

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c *.tmp_versions *.unsigned
	rm -f modules.order  Module.symvers
.PHONY:
	modules modules_install clean
else
obj-m := flashhack_http.o flashhack_tcp.o flashhack_all.o flashhack_out.o
endif

