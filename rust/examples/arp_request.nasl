if(description) {
  script_oid("1.2.3");
  exit(0);
}

display(send_arp_request(pcap_timeout: 2));
