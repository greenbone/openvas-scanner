#ifndef SAVE_TESTS_H__
#define SAVE_TESTS_H__


int save_tests_init(struct arglist *);
void save_tests_close(struct arglist*);


void save_tests_write_data(struct arglist *, char *);
void save_tests_host_done(struct arglist*, char*);

void save_tests_playback(struct arglist *, char *, harglst*);
int save_tests_setup_playback(struct arglist *, char *);

int save_tests_delete(struct arglist*, char *);
int save_tests_send_list(struct arglist*);


int save_tests_empty(struct arglist*);
int save_tests_delete_current(struct arglist*);
#endif
