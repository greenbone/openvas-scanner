#include <includes.h>
#include <errno.h>

#include "error_dialog.h"
#include "globals.h"

#ifdef HAVE__STAT
typedef struct _stat struct_stat ;
# ifndef S_ISREG
# define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
# endif
# define lstat(x,y) _stat(x,y)
#else
typedef struct stat struct_stat ;
# ifndef HAVE_LSTAT
#  define lstat(x,y) stat(x,y)
# endif
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((__ptr_t) -1)
#endif

char * target_file_to_list(filename)
 char * filename;
{
 HANDLE fd = open(filename, O_RDONLY);
 char * ret,*t;
 int len;
 struct_stat sb;
 int n, i, offs, left ;

 if(fd < 0)
   {
  char * text = emalloc(strlen(filename)+300);
  sprintf(text,"Could not open %s\nopen(%s) : %s\n", filename, filename, strerror(errno));
  if(F_quiet_mode)fprintf(stderr, "%s", text);
  efree(&text);
  return(NULL);
   }
   
 if (lstat (filename, &sb) != 0) {
   char * text = emalloc(strlen(filename)+300);
   sprintf(text, "Cannot stat %s (%s)\n", filename, strerror(errno));
   if (F_quiet_mode) fprintf (stderr, "%s", text);
   efree (&text);
   return 0;
 }
 len = (int)sb.st_size;
 ret = emalloc (len) ;
 offs =   0 ;
 left = len ;

 do {
   if ((n = read (fd, ret + offs, left)) < 0) {
     char * text = emalloc(strlen(filename)+300);
     efree(&ret);
     if (n == 0)
       sprintf(text, "file mapping failed: unexpected end-of-file\n");
     else  
       sprintf(text, "file mapping failed: %s\n", strerror(errno));
     if(F_quiet_mode)fprintf(stderr, "%s", text);
     efree (&text);
     return 0;
   }
 } while (offs += n, (left -= n) > 0) ;


 t = ret;
 while((t=strchr(t, '\n')))t[0]=',';
 t = ret;
 while((t=strchr(t, '\r')))t[0]=' ';
 i = strlen(ret);
 /*
  * trailing garbage
  */
 
 len = strlen(ret);
 while(len > 0 && ( ret[len-1]==',' || ret[len-1] == ' ' ) )
 {
   ret[len-1]='\0'; 
   len--; 
 }
 return(ret);
}
