obj-m := awdog.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MODULE := $(PWD)/awdog.ko
DUMMY_MODULE := $(PWD)/awdog_dummy.ko
INSTALL_DIR := /lib/modules/$(shell uname -r)/extra
MOKDIR := $(HOME)/mok
SIGN_PRIV := $(MOKDIR)/MOK.priv
SIGN_DER  := $(MOKDIR)/MOK.der
TEST_CFLAGS := -DAWDOG_TEST_MODE=1

.PHONY: all all_dummy clean sign sign_dummy sign_production sign_devmachine install install_dummy uninstall uninstall_dummy

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

all_dummy:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(TEST_CFLAGS)" modules
	cp -v "$(MODULE)" "$(DUMMY_MODULE)"
	@echo "[✓] Built dummy module: $(DUMMY_MODULE)"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	-rm -vf "$(DUMMY_MODULE)"

sign:
	@echo "[+] Signing $(MODULE)"
	sign-file sha256 "$(SIGN_PRIV)" "$(SIGN_DER)" "$(MODULE)"
	@modinfo "$(MODULE)" | egrep 'signer|sig_key|sig_hashalgo'

sign_dummy: all_dummy
	@echo "[+] Signing $(DUMMY_MODULE)"
	sign-file sha256 "$(SIGN_PRIV)" "$(SIGN_DER)" "$(DUMMY_MODULE)"
	@modinfo "$(DUMMY_MODULE)" | egrep 'filename|signer|sig_key|sig_hashalgo'

sign_production: sign

sign_devmachine: sign

install: sign
	@echo "[+] Installing $(MODULE) to $(INSTALL_DIR)/"
	mkdir -p "$(INSTALL_DIR)"
	cp -v "$(MODULE)" "$(INSTALL_DIR)/"
	depmod -a
	modprobe awdog
	@echo "[✓] awdog module installed and loaded"

install_dummy: sign_dummy
	@echo "[+] Installing $(DUMMY_MODULE) to $(INSTALL_DIR)/"
	mkdir -p "$(INSTALL_DIR)"
	cp -v "$(DUMMY_MODULE)" "$(INSTALL_DIR)/awdog_dummy.ko"
	depmod -a
	-modprobe -r awdog
	insmod "$(INSTALL_DIR)/awdog_dummy.ko"
	@echo "[✓] awdog dummy module installed and loaded (TEST MODE)"

uninstall:
	@echo "[+] Removing awdog module"
	-modprobe -r awdog
	-rm -vf "$(INSTALL_DIR)/awdog.ko"
	depmod -a

uninstall_dummy:
	@echo "[+] Removing awdog dummy module"
	-modprobe -r awdog
	-rm -vf "$(INSTALL_DIR)/awdog_dummy.ko"
	depmod -a


# needed to install tmp2-tss-devel on fedora
