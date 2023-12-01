# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

## Dependency checks
##

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (GLIB_JSON REQUIRED json-glib-1.0>=1.4.4)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.6.4)
pkg_check_modules (CURL REQUIRED libcurl>=7.74.0)

pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=22.4)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=22.4)
pkg_check_modules (LIBGVM_BOREAS REQUIRED libgvm_boreas>=22.4)

pkg_check_modules (OPENVAS_WMICLIENT libopenvas_wmiclient>=1.0.5)

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)
message (STATUS "Looking for pcap... ${PCAP}")
if (NOT PCAP)
  message (SEND_ERROR "The pcap library is required.")
endif (NOT PCAP)

message (STATUS "Looking for pcap-config...")
find_program (PCAP_CONFIG pcap-config)

if (PCAP_CONFIG)
  message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
  execute_process (COMMAND pcap-config --libs
    OUTPUT_VARIABLE PCAP_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string(STRIP ${PCAP_LDFLAGS} PCAP_LDFLAGS)
  execute_process (COMMAND pcap-config --cflags
    OUTPUT_VARIABLE PCAP_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
else (PCAP_CONFIG)
  message (STATUS "pcap-config not found, using defaults...")
  set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
  set (PCAP_CFLAGS "-I/usr/include")
endif (PCAP_CONFIG)

message (STATUS "Looking for gpgme...")
find_library (GPGME gpgme)
message (STATUS "Looking for gpgme... ${GPGME}")
if (NOT GPGME)
  message (SEND_ERROR "The gpgme library is required.")
endif (NOT GPGME)

execute_process (COMMAND gpgme-config --libs
  OUTPUT_VARIABLE GPGME_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND gpgme-config --cflags
  OUTPUT_VARIABLE GPGME_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")


## Pass-throughs
add_definitions (-DOPENVAS_MISC_VERSION="${PROJECT_VERSION_STRING}")

include_directories (${GLIB_INCLUDE_DIRS} ${GLIB_JSON_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS}
                     ${GNUTLS_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})

# Library

set (FILES bpf_share.c ftp_funcs.c vendorversion.c network.c plugutils.c pcap.c
     scan_id.c strutils.c table_driven_lsc.c ipc.c ipc_openvas.c ipc_pipe.c
     user_agent.c scanneraux.c kb_cache.c heartbeat.c)

# On windows we are always PIC and stack-protector is replaces by DEP
# Also stack protection needs a shared library to work
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

# Build shared

add_library (openvas_misc_shared SHARED ${FILES})

set_target_properties (openvas_misc_shared PROPERTIES OUTPUT_NAME "openvas_misc")
set_target_properties (openvas_misc_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_misc_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
set_target_properties (openvas_misc_shared PROPERTIES VERSION "${PROJECT_VERSION_STRING}")

target_link_libraries (openvas_misc_shared LINK_PRIVATE
                       ${GNUTLS_LDFLAGS} ${UUID_LDFLAGS}
                       ${GLIB_LDFLAGS} ${GLIB_JSON_LDFLAGS}
                       ${PCAP_LDFLAGS} ${LIBGVM_BOREAS_LDFLAGS} ${CURL_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR="${OPENVAS_DATA_DIR}")
endif (OPENVAS_DATA_DIR)

# @todo Why is this definition setting guarded? OPENVAS_SYSCONF_DIR should
#       always be set.
#$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c
if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
endif (OPENVAS_SYSCONF_DIR)

# install library

install (TARGETS openvas_misc_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR})

install (DIRECTORY DESTINATION ${GVM_LOG_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_DATA_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_SYSCONF_DIR})
install (DIRECTORY
  DESTINATION ${OPENVAS_SYSCONF_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
install (DIRECTORY
  DESTINATION ${OPENVAS_STATE_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)

## Tests

enable_testing ()

set (LINK_LIBS_FOR_TESTS cgreen
                       ${LIBGVM_BASE_LDFLAGS}
                       ${GLIB_LDFLAGS}
                       ${PCAP_LDFLAGS}
                       ${CURL_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT}
                       ${ALIVEDETECTION_TEST_LINKER_WRAP_OPTIONS})

set (ALIVEDETECTION_TEST_LINKER_WRAP_OPTIONS
  "-Wl,-wrap,socket,-wrap,setsockopt")

# pcap-tests
add_executable (pcap-test EXCLUDE_FROM_ALL pcap_tests.c)
add_test (pcap-test pcap-test)
target_include_directories (pcap-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (pcap-test cgreen
                       ${LIBGVM_BASE_LDFLAGS}
                       ${GLIB_LDFLAGS}
                       ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT}
                       ${ALIVEDETECTION_TEST_LINKER_WRAP_OPTIONS})
add_custom_target (tests-pcap
                  DEPENDS pcap-test)

# ipc-openvas-tests
add_executable (ipc-openvas-test EXCLUDE_FROM_ALL ipc_openvas_tests.c)
add_test (ipc-openvas-test ipc-openvas-test)
target_include_directories (ipc-openvas-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (ipc-openvas-test cgreen
                       ${GLIB_LDFLAGS}
                       ${GLIB_JSON_LDFLAGS}
                       ${CURL_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

add_custom_target (tests-ipc-openvas
                  DEPENDS ipc-openvas-test)

# lsc-tests
add_executable (lsc-test EXCLUDE_FROM_ALL table_driven_lsc_tests.c kb_cache.c plugutils.c scan_id.c)
add_test (lsc-test lsc-test)
target_include_directories (lsc-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (lsc-test cgreen
                       ${LIBGVM_BASE_LDFLAGS}
                       ${LIBGVM_UTIL_LDFLAGS}
                       ${GLIB_LDFLAGS}
                       ${GLIB_JSON_LDFLAGS}
                       ${CURL_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

add_custom_target (tests-lsc
                  DEPENDS lsc-test)

## End
