#ifndef SHARED_SOCKET_H__
#define SHARED_SOCKET_H__



int shared_socket_init();
int shared_socket_process( int, nthread_t, char *, int );
int shared_socket_cleanup_process(nthread_t);
int shared_socket_close();


#endif
