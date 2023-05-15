# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

## build

include (FindDoxygen)

if (NOT DOXYGEN_EXECUTABLE)
  message (STATUS "WARNING: Doxygen is required to build the HTML docs.")
else (NOT DOXYGEN_EXECUTABLE)
  configure_file (Doxyfile.in Doxyfile @ONLY)
  configure_file (Doxyfile_full.in Doxyfile_full @ONLY)
  configure_file (Doxyfile_xml.in Doxyfile_xml @ONLY)

  add_custom_target (doxygen COMMENT "Building documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/.built-html)

  add_custom_command (OUTPUT .built-html
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-html\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

  add_custom_target (doxygen-full COMMENT "Building documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full ${CMAKE_CURRENT_BINARY_DIR}/.built-html_full)

  add_custom_command (OUTPUT .built-html_full
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-html_full\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full)

  add_custom_target (doxygen-xml COMMENT "Building documentation (XML)..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml ${CMAKE_CURRENT_BINARY_DIR}/.built-xml)

  add_custom_command (OUTPUT .built-xml
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-xml\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml)
endif (NOT DOXYGEN_EXECUTABLE)


find_program(PANDOC pandoc)

if (NOT PANDOC)
  message(STATUS "WARNING: pandoc is required to build the HTML user manual.")
else (NOT PANDOC)
  configure_file(man.sh man.sh @ONLY)
  configure_file(html.sh html.sh @ONLY)
  file(COPY manual DESTINATION .)
  file(COPY templates DESTINATION .)

  add_custom_target(manual COMMAND ${CMAKE_CURRENT_BINARY_DIR}/html.sh)
  add_custom_target(nasl-man COMMAND ${CMAKE_CURRENT_BINARY_DIR}/man.sh)
endif (NOT PANDOC)
