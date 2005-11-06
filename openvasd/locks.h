#ifndef _NESSUSD_LOCKS_H__
#define _NESSUSD_LOCKS_H__

int file_lock(char *);
int file_unlock(char *);
int file_locked(char *);

#endif /* _NESSUSD_LOCKS_H__ */
