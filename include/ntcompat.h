/* OpenVAS
* $Id$
* Description: Defines for Windows NT compatibility.
*
* Authors: - Renaud Deraison <deraison@nessus.org> (Original pre-fork develoment)
*          - Tim Brown <mailto:timb@openvas.org> (Initial fork)
*          - Laban Mwangi <mailto:labanm@openvas.org> (Renaming work)
*          - Tarik El-Yassem <mailto:tarik@openvas.org> (Headers section)
*
* Copyright:
* Portions Copyright (C) 2006 Software in the Public Interest, Inc.
* Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2,
* as published by the Free Software Foundation
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
*
*/


#ifndef NESSUS_NT_COMPAT__
#define NESSUS_NT_COMPAT__
 
/*
 * ntcompat.h : redefinition of several system calls to provide
 *              NT compatibility to OpenVAS
 *
 */

#ifdef NESSUSNT
#include <windows.h>
#endif


/*
 * Thread management
 */
 
typedef int(*thread_func_t)(void *);

#ifdef USE_NT_THREADS
typedef HANDLE nthread_t;
#define EXIT(x) ExitThread(x)
#define _EXIT(x) ExitThread(x)
#define DO_EXIT(x) exit(x)
#define TERMINATE_THREAD(x) TerminateThread(x,0)
#endif /* US_NT_THREADS */

#ifdef USE_FORK_THREADS
typedef int nthread_t;
#define EXIT(x) exit(x)
#ifdef HAVE__EXIT
#define _EXIT(x) _exit(x)
#else
#define _EXIT(x) exit(x)
#endif
#define DO_EXIT(x) exit(x)
#define TERMINATE_THREAD(x) {if(x > 0)kill(x, SIGTERM);}
#endif /* USE_FORK_THREADS */

#ifdef USE_PTHREADS
/*
 * I hate pthreads
 */
typedef struct {
   pthread_t thread;
   pthread_mutex_t mutex;
   int ready;
   } _nthread_t,*nthread_t;
   
struct thread_args {
    void * arg;
    pthread_mutex_t * mutex;
    thread_func_t func;
    nthread_t thread;
    };
#define EXIT(x) exit_pthread(x)
#define _EXIT(x) EXIT(x)
#define DO_EXIT(x) exit(x)

#ifdef HAVE_PTHREAD_CANCEL
#define TERMINATE_THREAD(x) {pthread_cancel(x->thread);pthread_detach(x->thread);}
#else
#warning "Your system lacks pthread_cancel() ! Using the pthreads is not recommanded"
#define TERMINATE_THREAD(x)
#endif /* HAVE_PTHREAD_CANCEL */
#endif /* USE_PTHREADS */



/*
 * External libraries management
 */
#ifdef NESSUSNT
typedef HMODULE ext_library_t;
#define LOAD_FUNCTION(x,y) GetProcAddress(x,y)
#define LOAD_LIBRARY(x) LoadLibrary(x)
#define LIB_LAST_ERROR WSAGetLastError
#define CLOSE_LIBRARY(x) FreeLibrary(x)
#else
typedef void * ext_library_t;
#define LOAD_FUNCTION(x,y) dlsym(x,y)

#ifdef RTLD_NOW
#define LOAD_LIBRARY(x) dlopen(x,RTLD_NOW)
#else
#define LOAD_LIBRARY(x) dlopen(x, 1)
#endif /* not defined(RTLD_NOW) */

#define LIB_LAST_ERROR dlerror
#define CLOSE_LIBRARY(x) dlclose(x)
#endif /* defined(NESSUSNT) */


/*
 * Misc. functions
 */
#ifdef NESSUSNT
#ifndef __STDC__
#define __STDC__ 1
#endif
#define getpid(x) GetCurrentProcessId(x)
#define close(x)  closesocket(x)
#define ioctl(x,y,z) ioctlsocket(x,y,z)
#define signal(x,y)
#define alarm(x)
#define chmod(x,y)
#define getopt(x,y,z) EOF
typedef unsigned int u_int32_t;
typedef unsigned short n_short;
typedef unsigned short u_short;
typedef unsigned short u_int16_t;
typedef unsigned long n_time;
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#endif /* defined(NESSUSNT) */

#ifndef NESSUSNT
#define print_error printf
#endif



#ifdef NESSUSNT
#define DllExport __declspec (dllexport)
#define DllImport __declspec  (dllimport)
#define PlugExport DllExport

#ifdef EXPORTING
#define ExtFunc DllExport
#else
#define ExtFunc DllImport
#endif /* defined(EXPORTING) */

#else /* !NESSUSNT */

#define PlugExport
#define DllExport
#define DllImport
#define ExtFunc

#endif /* defined(NESSUSNT) */

#endif /* defined(NESSUS_NT_COMPAT_H) */
