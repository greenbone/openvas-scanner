KRB5_VERSION := 1.22.2
KRB5_SERIES := $(basename $(KRB5_VERSION))
VENDOR_DIR := vendor
KRB5_TARBALL := $(VENDOR_DIR)/krb5-$(KRB5_VERSION).tar.gz

.PHONY: vendor

vendor:
	mkdir -p $(VENDOR_DIR)
	curl -L -o $(KRB5_TARBALL) https://kerberos.org/dist/krb5/$(KRB5_SERIES)/krb5-$(KRB5_VERSION).tar.gz
	rm -rf $(VENDOR_DIR)/krb5-$(KRB5_VERSION)
	tar -xzf $(KRB5_TARBALL) -C $(VENDOR_DIR)
	rm -f $(KRB5_TARBALL)
	rm -rf \
		$(VENDOR_DIR)/krb5-$(KRB5_VERSION)/.github \
		$(VENDOR_DIR)/krb5-$(KRB5_VERSION)/doc \
		$(VENDOR_DIR)/krb5-$(KRB5_VERSION)/src/ccapi \
		$(VENDOR_DIR)/krb5-$(KRB5_VERSION)/src/po \
		$(VENDOR_DIR)/krb5-$(KRB5_VERSION)/src/prototype \
		$(VENDOR_DIR)/krb5-$(KRB5_VERSION)/src/windows
