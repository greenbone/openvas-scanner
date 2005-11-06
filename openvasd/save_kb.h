#ifndef SAVE_KB_H__
#define SAVE_KB_H__


int save_kb_new(struct arglist*, char *);
void save_kb_close(struct arglist*, char*);

int save_kb_backup(struct arglist*, char*);
int save_kb_restore_backup(struct arglist*, char*);

int save_kb_write_int(struct arglist*, char*, char*, int);
int save_kb_write_str(struct arglist*, char*, char*, char*);

int save_kb_exists(struct arglist*, char*);
struct kb_item ** save_kb_load_kb(struct arglist*, char*);

/*
 * Preferences set by the user
 */
int save_kb(struct arglist*);
int save_kb_pref_tested_hosts_only(struct arglist*);
int save_kb_pref_untested_hosts_only(struct arglist*);
int save_kb_pref_restore(struct arglist*);
int save_kb_replay_check(struct arglist*, int);
long save_kb_max_age(struct arglist*);


int diff_scan(struct arglist*);
void diff_scan_enable(struct arglist*);
#endif
