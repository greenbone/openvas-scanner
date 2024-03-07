# License information about openvas-scanner

The effective license of the modules as a whole
is the GNU General Public License Version 2 (GNU GPL-2).

Single files, however, are licensed either
under GNU General Public License Version 2 (GNU GPL-2)
or under "GNU GPLv2 or any later version" (GNU GPL-2+).

GPL-2: See file [COPYING](COPYING)

The following list was created using the 'licensecheck'
tool with the following command:

```
licensecheck -r --deb-fmt <directory>
```

src/CMakeLists.txt: GPL-2+
src/attack.c: GPL-2
src/attack.h: GPL-2
src/attack_tests.c: GPL-2+
src/debug_utils.c: GPL-2+
src/debug_utils.h: GPL-2+
src/hosts.c: GPL-2
src/hosts.h: GPL-2
src/main.c: GPL-2+
src/nasl_plugins.c: GPL-2
src/openvas.c: GPL-2
src/openvas.h: GPL-2+
src/pluginlaunch.c: GPL-2
src/pluginlaunch.h: GPL-2
src/pluginload.c: GPL-2
src/pluginload.h: GPL-2
src/pluginscheduler.c: GPL-2
src/pluginscheduler.h: GPL-2
src/plugs_req.c: GPL-2
src/plugs_req.h: GPL-2
src/processes.c: GPL-2
src/processes.h: GPL-2
src/sighand.c: GPL-2
src/sighand.h: GPL-2
src/utils.c: GPL-2
src/utils.h: GPL-2

nasl/CMakeLists.txt: GPL-2+
nasl/arc4.c: GPL-2+
nasl/byteorder.h: GPL-2+
nasl/capture_packet.c: GPL-2
nasl/capture_packet.h: GPL-2
nasl/charcnv.c: GPL-2+
nasl/charset.h: GPL-2+
nasl/exec.c: GPL-2
nasl/exec.h: GPL-2
nasl/genrand.c: GPL-2+
nasl/hmacmd5.c: GPL-2+
nasl/hmacmd5.h: GPL-2+
nasl/iconv.c: GPL-2+
nasl/iconv.h: GPL-2+
nasl/lint.c: GPL-2
nasl/lint.h: GPL-2
nasl/md4.c: GPL-2+
nasl/md4.h: GPL-2+
nasl/md5.c: public-domain
nasl/md5.h: public-domain
nasl/nasl-lint.c: GPL-2+
nasl/nasl.c: GPL-2
nasl/nasl.h: GPL-2
nasl/nasl_builtin_find_service.c: GPL-2
nasl/nasl_builtin_openvas_tcp_scanner.c: GPL-2
nasl/nasl_builtin_plugins.h: GPL-2+
nasl/nasl_builtin_synscan.c: GPL-2
nasl/nasl_cert.c: GPL-2+
nasl/nasl_cert.h: GPL-2+
nasl/nasl_cmd_exec.c: GPL-2
nasl/nasl_cmd_exec.h: GPL-2
nasl/nasl_crypt_helper.c: GPL-2
nasl/nasl_crypto_helper.h: GPL-2
nasl/nasl_crypto.c: GPL-2
nasl/nasl_crypto.h: GPL-2
nasl/nasl_crypto2.c: GPL-2
nasl/nasl_crypto2.h: GPL-2
nasl/nasl_debug.c: GPL-2
nasl/nasl_debug.h: GPL-2
nasl/nasl_frame_forgery.c: GPL-2+
nasl/nasl_frame_forgery.h: GPL-2+
nasl/nasl_func.c: GPL-2
nasl/nasl_func.h: GPL-2
nasl/nasl_global_ctxt.h: GPL-2
nasl/nasl_grammar.y: GPL-2
nasl/nasl_host.c: GPL-2
nasl/nasl_host.h: GPL-2
nasl/nasl_http.c: GPL-2
nasl/nasl_http.h: GPL-2
nasl/nasl_init.c: GPL-2
nasl/nasl_init.h: GPL-2
nasl/nasl_isotime.c: GPL-2+
nasl/nasl_isotime.h: GPL-2+
nasl/nasl_lex_ctxt.c: GPL-2
nasl/nasl_lex_ctxt.h: GPL-2
nasl/nasl_misc_funcs.c: GPL-2
nasl/nasl_misc_funcs.h: GPL-2
nasl/nasl_packet_forgery.c: GPL-2
nasl/nasl_packet_forgery.h: GPL-2
nasl/nasl_packet_forgery_v6.c: GPL-2
nasl/nasl_packet_forgery_v6.h: GPL-2
nasl/nasl_raw.h: GPL-2
nasl/nasl_scanner_glue.c: GPL-2
nasl/nasl_scanner_glue.h: GPL-2
nasl/nasl_signature.c: GPL-2+
nasl/nasl_signature.h: GPL-2+
nasl/nasl_smb.c: GPL-2+
nasl/nasl_smb.h: GPL-2+
nasl/nasl_snmp.c: GPL-2+
nasl/nasl_snmp.h: GPL-2+
nasl/nasl_socket.c: GPL-2
nasl/nasl_socket.h: GPL-2
nasl/nasl_ssh.c: GPL-2+
nasl/nasl_ssh.h: GPL-2+
nasl/nasl_text_utils.c: GPL-2
nasl/nasl_text_utils.h: GPL-2
nasl/nasl_tree.c: GPL-2
nasl/nasl_tree.h: GPL-2
nasl/nasl_var.c: GPL-2
nasl/nasl_var.h: GPL-2
nasl/nasl_wmi.c: GPL-2+
nasl/nasl_wmi.h: GPL-2+
nasl/ntlmssp.c: GPL-2+
nasl/ntlmssp.h: GPL-2+
nasl/openvas_smb_interface.h: GPL-2+
nasl/openvas_wmi_interface.h: GPL-2+
nasl/proto.h: GPL-2+
nasl/smb.h: GPL-2+
nasl/smb_crypt.c: GPL-2+
nasl/smb_crypt.h: GPL-2+
nasl/smb_crypt2.c: GPL-2+
nasl/smb_interface_stub.c: GPL-2+
nasl/smb_signing.c: GPL-2+
nasl/smb_signing.h: GPL-2+
nasl/time.c: GPL-2+
nasl/wmi_interface_stub.c: GPL-2+

nasl/tests/Makefile: GPL-2+
nasl/tests/signed.nasl: GPL-2+
nasl/tests/test_blowfish.nasl: GPL-2+
nasl/tests/test_bn.nasl: GPL-2+
nasl/tests/test_crypt_data_aes.nasl: GPL-2+
nasl/tests/test_dh.nasl: GPL-2+
nasl/tests/test_dsa.nasl: GPL-2+
nasl/tests/test_hexstr.nasl: GPL-2+
nasl/tests/test_isotime.nasl: GPL-2+
nasl/tests/test_md.nasl: GPL-2+
nasl/tests/test_privkey.nasl: GPL-2+
nasl/tests/test_rsa.nasl: GPL-2+
nasl/tests/test_socket.nasl: GPL-2+
nasl/tests/testsuiteinit.nasl: GPL-2+
nasl/tests/testsuitesummary.nasl: GPL-2+

misc/CMakeLists.txt: GPL-2+
misc/bpf_share.c: GPL-2
misc/bpf_share.h: GPL-2+
misc/ftp_funcs.c: GPL-2+
misc/ftp_funcs.h: GPL-2+
misc/ipc.c: GPL-2+
misc/ipc.h: GPL-2+
misc/ipc_openvas.c: GPL-2+
misc/ipc_openvas.h: GPL-2+
misc/ipc_pipe.c: GPL-2+
misc/ipc_pipe.h: GPL-2+
misc/network.c: GPL-2+
misc/network.h: GPL-2+
misc/nvt_categories.h: GPL-2+
misc/pcap.c: GPL-2+
misc/pcap_openvas.h: GPL-2+
misc/pcap_tests.c: GPL-2+
misc/plugutils.c: GPL-2+
misc/plugutils.h: GPL-2+
misc/scan_id.c: GPL-2+
misc/scan_id.h: GPL-2+
misc/scanneraux.h: GPL-2+
misc/strutils.c: GPL-2+
misc/strutils.h: GPL-2+
misc/support.h: GPL-2+
misc/table_driven_lsc.c: GPL-2+
misc/table_driven_lsc.h: GPL-2+
misc/vendorversion.c: GPL-2+
misc/vendorversion.h: GPL-2+
