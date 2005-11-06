#ifndef NESSUSD_DETACHED_H__
#define NESSUSD_DETACHED_H__

#ifdef ENABLE_SAVE_KB
int  detached_setup_mail_file(struct arglist*, char*);
void detached_copy_data(struct arglist*, char*, int);
void detached_send_email(struct arglist*);


int detached_new_session(struct arglist *, char *);
int detached_end_session(struct arglist *);
int detached_delete_session(struct arglist *, int);

int detached_send_sessions(struct arglist *);
#endif
#endif
