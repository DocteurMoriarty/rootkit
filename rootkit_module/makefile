obj-m += rootkit.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
	gcc -Wall -Wextra -o rootkit core.c
clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f rootkit
