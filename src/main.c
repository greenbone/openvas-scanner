/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file  main.c
 * @brief Main function of openvas.
 *
 * This file separates out the "main" function of openvas.
 */

#include "openvas.h"

/**
 * @brief Main function.
 *
 * @param[in]  argc  The number of arguments in argv.
 * @param[in]  argv  The list of arguments to the program.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
main (int argc, char **argv, char *env[])
{
  return openvas (argc, argv, env);
}
