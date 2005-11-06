#ifndef NESSUS_NT_COMPAT__
#define NESSUS_NT_COMPAT__
/*
 * This file is subject to the GPL
 *
 * (c) 1998 Renaud Deraison <deraison@worldnet.fr>
 *
 * ntcompat.h : redefinition of several system calls to provide
 *              NT compatibility to Nessus
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
#ifndef USE_GTK
/* so we are not on the nessus client */
#define getpid(x) GetCurrentProcessId(x)
#define close(x)  closesocket(x)
#endif /* USE_GTK */
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
