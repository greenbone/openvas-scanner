#ifndef NESSUSD_PLUGS_HASH_H__
#define NESSUSD_PLUGS_HASH_H__

char * file_hash(char *);
char * plugins_hash(struct arglist *);
void plugins_send_md5(struct arglist*);

#endif
