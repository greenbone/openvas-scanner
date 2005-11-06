#ifndef NESSUSD_MD5_H
#define NESSUSD_MD5_H

#define md5_ctx void

md5_ctx * md5init();
void md5free(md5_ctx *); 
void md5update(md5_ctx *, char *, int );
char * md5final(md5_ctx *);

char * md5sum(char*, int);


#ifndef HAVE_SSL
char * rsaMD5(char*, int, u_char*);
#define MD5(x,y,z) rsaMD5(x,y,z)
#endif

#endif
