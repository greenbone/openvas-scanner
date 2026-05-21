KRB5_VERSION := 1.22.2
KRB5_SERIES := $(basename $(KRB5_VERSION))
LIBPCAP_VERSION := 1.10.6

VENDOR_DIR := vendor
KRB5_TARBALL := $(VENDOR_DIR)/krb5-$(KRB5_VERSION).tar.gz
LIBPCAP_TARBALL := $(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION).tar.gz

.PHONY: all vendor

all: vendor

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
	curl -L -o $(LIBPCAP_TARBALL) https://www.tcpdump.org/release/libpcap-$(LIBPCAP_VERSION).tar.gz
	rm -rf $(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION)
	tar -xzf $(LIBPCAP_TARBALL) -C $(VENDOR_DIR)
	rm -f $(LIBPCAP_TARBALL)
	rm -rf \
		$(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION)/doc \
		$(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION)/tests \
		$(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION)/cmake \
		$(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION)/msdos \
		$(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION)/ChmodBPF
