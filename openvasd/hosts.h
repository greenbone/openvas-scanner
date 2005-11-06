#ifndef HOSTS_H
#define HOSTS_H


int hosts_init(int, int);
int hosts_new(struct arglist *, char*);
int hosts_set_pid(char*, pid_t);
int hosts_read(struct arglist *);
void hosts_stop_all();
int hosts_stop_host(struct arglist * globals, char *);

#endif
