#ifndef _GVM_LIBS_MACROS_H
#define _GVM_LIBS_MACROS_H

#include <glib.h>
#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION >= 68
#undef g_memdup
#define g_memdup g_memdup2
#endif

#endif
