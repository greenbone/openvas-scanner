LIBPCAP_VERSION := 1.10.6

VENDOR_DIR := vendor
LIBPCAP_TARBALL := $(VENDOR_DIR)/libpcap-$(LIBPCAP_VERSION).tar.gz

.PHONY: all vendor

all: vendor

vendor:
	mkdir -p $(VENDOR_DIR)
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
