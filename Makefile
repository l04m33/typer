OBJNAME:=typer
obj-m += $(OBJNAME).o
KDIR:=/usr/src/kernels/`uname -r`

EXTRA_CFLAGS+= -DTYPER_DEBUG -g 

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -v $(OBJNAME).ko $(OBJNAME).mod.c $(OBJNAME).mod.o $(OBJNAME).o \
	      Module.symvers .$(OBJNAME).ko.cmd .$(OBJNAME).mod.o.cmd \
		  .$(OBJNAME).o.cmd Module.markers modules.order
	rm -vr .tmp_versions

