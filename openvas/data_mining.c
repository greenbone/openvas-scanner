/* Nessus
 * Copyright (C) 1998, 1999, 2000, 2001 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 *
 *  Functions to explore a report. Note that this code can easily be
 *  changed to be linked to any database instead of the simple
 *  flat files that are currently used.
 *
 *  This file implements subset selection in the report as well
 *  as the implementation of a light query language.
 *
 *  Modified by Axel Nennker axel@nennker.de 20020306
 *  Removed unused variables and format string errors.
 *
 */
 

#include <includes.h>
#include <stdarg.h>
#include "backend.h"
#include "data_mining.h"


#ifndef MIN
#define MIN(x,y) ((x<y)?(x):(y))
#endif


#ifdef HAVE_MMAP
#ifndef MAP_FAILED
#define MAP_FAILED (void*)-1
#endif
#endif


extern struct backend backends[];


static int __split_line(char*, char**, char**, char**, char**, char**, char**, char**);

/*----------------------------------------------------------------*
 * Private utilities                                              *
 *----------------------------------------------------------------*/
 
#ifdef HAVE_MMAP
static int 
be_index_keywords(be)
{
  int i;
  char * field[BE_NUM_FIELDS];
  static char * buf = NULL;
  static int bufsz = 0;


  if ( buf == NULL )
  {
   bufsz = 1024 * 1024;
   buf   = emalloc ( bufsz );
  }
  
  
  if(backends[be].fields)
  	return 0;
	
  backends[be].fields = emalloc(BE_NUM_FIELDS * sizeof(*backends[be].fields));
  for(i=0;i<backends[be].num_lines;i++)
  {
  int len;
  int j;
  char * sol = backends[be].lines[i];
  char * eol = backends[be].eols[i];
  
  
  if(eol)
  {
   len = (int)(eol - sol);
   memcpy(buf, sol, MIN(len, bufsz));
  }
  else
  {
   len = strlen(backends[be].lines[i]);
   memcpy(buf, backends[be].lines[i], MIN(bufsz, len));
  }
  
  __split_line(buf, &field[0], &field[1], &field[2], &field[3], &field[4], &field[5], &field[6]);
  
  /*
   * We don't index the last field (the data), hence the BE_NUM_FIELDS-1
   */
  for(j=0;j<BE_NUM_FIELDS-1;j++)
  {
   struct field * f;
   int flag = 0;
   
   
   
    if(!field[j])
     	continue;
	
   f = backends[be].fields[j];	
   while(f)
    {
     if(!strcmp(f->value, field[j]))
     {
      f->lines[f->num_lines++] = i;
      if(f->num_lines >= f->allocated_lines)
      {
       f->allocated_lines *= 2;
       f->lines = realloc(f->lines, f->allocated_lines*sizeof(int));
      }
      flag = 1;
      break;
     }
     f = f->next;
    }
    
    if(!flag)
    {
     if ( field[j] == NULL )
       	return -1;
    f = emalloc(sizeof(*f));
    f->value = emalloc(strlen(field[j])+1);
    strcpy(f->value, field[j]);
    f->lines = emalloc(sizeof(int)*5);
    f->allocated_lines = 5;
    f->num_lines = 1;
    f->lines[0] = i;  
    f->next = backends[be].fields[j];
    backends[be].fields[j] = f;
   }
  }

}
  
 for(i=0;i<6;i++)
 {
  struct field * f = backends[be].fields[i];
   while(f)
   {
    f->allocated_lines = f->num_lines;
    f->lines = realloc(f->lines, f->allocated_lines*sizeof(int));
    f = f->next;
   }
 } 
 return 0;
}

static void 
be_mk_index(be)
  int be;
 {
   int num_lines = 0;
   int num_allocated_lines = 65535;
   char ** lines;
   char ** eols;
   char * sol, * eol;
   
   lines = emalloc(num_allocated_lines*sizeof(*lines));
   eols  = emalloc(num_allocated_lines*sizeof(*eols));
   sol = backends[be].mmap;
  
   num_lines = 0;
   while(sol)
   {
    eol = strchr(sol, '\n');
    lines[num_lines] = sol;
    eols[num_lines] = eol;
    num_lines++;
    if(num_lines + 1 >= num_allocated_lines)
    {
     num_allocated_lines *= 2;
     lines = realloc(lines, num_allocated_lines*sizeof(*lines));
     eols = realloc(eols, num_allocated_lines*sizeof(*eols));
    }
    if(eol)sol = &(eol[1]);
    else sol = NULL;
   }
   backends[be].lines = realloc(lines, (num_lines + 1)*sizeof(*lines));
   backends[be].eols = realloc(eols, (num_lines + 1)*sizeof(*eols));
   backends[be].num_lines = num_lines;
   backends[be].lines[num_lines] = NULL;
   backends[be].eols[num_lines] = NULL;
   backends[be].cur_line = 0;
#ifdef DEBUG
   printf("data_mining.c: Finished the indexing - %d lines\n", num_lines);
#endif
   be_index_keywords(be);
}

#endif


#ifdef HAVE_MMAP
static int
mmap_read_line_n(be, buf, size, n)
 int be;
 char * buf;
 size_t size;
 int n;
{
 char* sol, * eol;
 if ( size <= 0 )
	return -1;
 size --;
 sol = backends[be].lines[n];
 if(!sol)
  return -1;
 eol = backends[be].eols[n];
 if(eol)
 {
   int line_len = (int)(eol - sol);
   memcpy(buf, sol, MIN(line_len, size));
   buf[MIN(line_len, size)] = '\0';
   backends[be].cur_line++;
   return MIN(line_len, size);
 }
 else
 {
   int len = strlen(backends[be].lines[n]);
   memcpy(buf, backends[be].lines[n], MIN(size, len));
   buf[MIN(size, len)] = '\0';
   backends[be].cur_line++;
   return MIN(size, len);		
 }
}
#endif

/*----------------------------------------------------------------------*
 * Returns one record (one line) read from the backend (flatfile)	*
 *									*
 * We use mmap() if possible, for speed sake. For extremely big files,  *
 * the use of a real database would be required.			*
 *									*
 *----------------------------------------------------------------------*/
static int 
read_line(be, buf, size)
 int be;
 char * buf;
 size_t size;
{
#ifdef HAVE_MMAP
 /* 
  * We always try to mmap() our file. If we don't have enough memory,
  * we expect the OS to not be dumb and return MAP_FAILED instead of
  * trying to fit 2Gb of data into memory
  *
  * We could probably improve that in the future by mapping only segments
  * of the file at once, thus allowing us to work on the file quite fast
  * (compared to just using read())
  *
  */
 if(!backends[be].mmap_attempts)
 {
  struct stat buf;
  int len;
  fstat(backends[be].fd, &buf);
  len = (int)buf.st_size;
  if((backends[be].mmap = 
   	mmap(NULL, len, PROT_READ, MAP_SHARED, backends[be].fd, 0)) 
			== MAP_FAILED)
   	backends[be].mmap = NULL;
  else
  	 be_mk_index(be);
  backends[be].mmap_attempts++;  
 }
 
 if(backends[be].mmap)
 {
  char * eol, *sol;
  int line_len;
  
  
  sol = backends[be].lines[backends[be].cur_line];
  if(!sol)
   {
  	return -1; /* eof */
   }
	
  eol = backends[be].eols[backends[be].cur_line];
  if ( size <= 0 )
	return -1;
  size --;
  
  if(eol)
  {
   line_len = (int)(eol - sol);
   memcpy(buf, sol, MIN(line_len, size));
   buf[MIN(line_len, size)] = '\0';
   backends[be].cur_line++;
   return line_len;
  }
  else
  {
   int len = strlen(backends[be].lines[backends[be].cur_line]);
   memcpy(buf, backends[be].lines[backends[be].cur_line], MIN(size, len));
   buf[len] = '\0';
   backends[be].cur_line++;
   return len;		
  }
 }
 else
#endif /* HAVE_MMAP */ 

 /* 
  * This part could be improved too. Rather than reading one byte
  * at a time, we could read, say, 255 bytes and use fseek() to
  * reset the position where needed.
  */
 {
 int tot = 1;
 bzero(buf, size);
   
   
   
 if(read(backends[be].fd, buf, 1) <= 0)
  return -1;
 while(buf[0] != '\n')
 {
  buf++;
  tot++;
  if(tot > size)
   return tot;
  if(read(backends[be].fd, buf, 1) < 0)
   return -1;
  }
  return tot;
 }
}


/*-----------------------------------------------------------------*
 		    SUBSET MANAGEMENT INTERFACE
 *-----------------------------------------------------------------*

  A subset contains the result of a query. It is made up of rows
  and fields (that we call values).
  To go from the current row to the next one, use the function
  subset_next(). To extract value of the values (fields),
  use subset_nth_value(). subset_value() is an alias for
  subset_nth_value(subset, 0), ie: it returns the first field
  (the only one which can not be NULL).
 
 
-------------------------------------------------------------------*/

struct subset *
subset_next(subset)
 struct subset * subset;
{
 return subset->next;
}





int 
subnet_num_values(subset)
 struct subset * subset;
{
 return subset->num_fields;
}


char *
subset_nth_value(subset, n)
 struct subset * subset;
 int n;
{
 if(n >= subset->num_fields)
  return NULL;
 return subset->data[n];
}

char *
subset_value(subset)
 struct subset * subset;
{
 return subset_nth_value(subset, 0);
}



/*
 * Add the value <value> in the subset
 */
static struct subset *
subset_add(subset, value)
 struct subset * subset;
 char * value;
{
 struct subset * ret;
 
 ret = emalloc(sizeof(*ret));
 ret->next = subset;
 ret->data = emalloc(sizeof(char*)*2);
 ret->num_fields = 1;
 ret->data[0] = rmslashes(value);
 ret->data[1] = NULL;
 return ret;
}


/*
 * Add another value (field) in the same row
 */
static struct subset *
subset_add_again(subset, value)
 struct subset * subset;
 char * value;
{
 struct subset * ret = subset;
 if(!subset)
  return subset_add(subset, value);
 ret->data = realloc(ret->data, (ret->num_fields+1)*sizeof(char*));
 ret->data[ret->num_fields] = rmslashes(value);
 ret->num_fields++;
 return ret;
}




/*-------------------------------------------------------------------------*
				Subset sorting
 --------------------------------------------------------------------------*/

static struct subset * 
merge_sort(list, n, m, cmp)
 struct subset * list;
 int n, m;
 cmp_func_t *cmp;
{
 struct subset * p, * q, * e, *tail;
 int insize = 1, nmerges, i;
 register int psize = 0, qsize = 0;

 for(;;)
 {
  p = list;
  list = tail = NULL;
  nmerges = 0;
  
  while  (p)
  {
   nmerges++; 
   q = p;
   for(i=0;i<insize;i++)
   { 
    psize++;
    q = q->next;
    if(!q)break;
   }
  
   qsize = insize;
   while((psize > 0) || ((qsize > 0) && q))
   {
    if(psize == 0)
    {
     e = q;
     q = q->next;
     qsize--;
    }
    else if(qsize == 0 || !q)
    { 
     e = p;
     p = p->next;
     psize--;
    }
    else 
    {
     int k;
     int p_smaller = 0;
   
     for(k=n;(k<=m) && (p_smaller==0);k++)
     {
   	char * a = subset_nth_value(p,k);
  	char * b = subset_nth_value(q,k);
   	p_smaller = cmp[k-n](a,b); 
     }
     
     if(p_smaller >= 0)
     {
     e = p; p = p->next;psize--;
     }
     else {
     e = q; q = q->next;
     qsize --;
    }
    }
    
   
   if(tail)
   {
    tail->next = e;
   }
    else
   {
    list = e;
   }
   tail = e;
   }
   p = q;
  }
   
   if(tail)tail->next = NULL;
   if(nmerges <= 1)
    {
    return list;
    }
   insize *= 2;
  }
}


/*
 * Entry point for the sort
 *
 * <subset> : the subset we want to sort
 * <field_start>,<field_end> : the fields we must sort the subset according
 * 				to
 *
 * <cmp> : an array of comparison functions. Each field can have its
 *         own comparison function.
 *
 */
struct subset  * 
subset_sort(subset, field_start, field_end, cmp)
 struct subset * subset;
 int field_start, field_end;
 cmp_func_t *cmp;
{
 return merge_sort(subset, field_start, field_end, cmp);
}



/*------------------------------------------------------------------------*
 * Other subset-related utilities					  *
 *------------------------------------------------------------------------*/
 
/*
 * Act as the uniq(1) unix utility -> two entries with the same
 * fields are removed.
 *
 * This function compares the <n> first fields.
 * (hence, subset_uniq(s, 0) will remove all duplicates in a list)
 *
 */
struct subset *
subset_uniq(subset, n)
 struct subset * subset;
 int n;
{
 struct subset * s = subset;
 if(!s)
  return NULL;
  
 while(subset->next)
 {
  int i;
  int removed = 0;
  for(i=0;i<=n;i++)
  {
  if(subset->data[i]       &&
     subset->next->data[i] &&
     !strcmp(subset->data[i], subset->next->data[i])
    )
   {
   struct subset * old = subset->next;
   subset->next = subset->next->next;
   old->next = NULL;
   subset_free(old);
   removed++;
   break;
   }
  }
  
  if(!removed)subset = subset->next;
  }
  return s;
}



/*
 * Tells us if the value <value> is already in the <nth> field of the current
 * row
 */ 
static char *
subset_in_nth(subset, value, n)
 struct subset * subset;
 char * value;
 int n;
{
 while(subset)
 {
  if(subset->data[n] && !strcmp(subset->data[n], value))
   return subset->data[n];
 subset = subset->next;
 }
 return NULL;
}


/*
 * An alias for the above function, for n = 0
 */
char *
subset_in(subset, value)
 struct subset * subset;
 char * value;
{
 return subset_in_nth(subset, value, 0);
}


/*
 * Frees a subset and associate fields from memory
 */
void
subset_free(subset)
 struct subset * subset;
{
 while(subset)
 {
  struct subset * next = subset->next;
  while(subset->num_fields > 0)
  {
   efree(&subset->data[subset->num_fields-1]);
   subset->num_fields --;
  }
  efree(&subset->data);
  efree(&subset);
  subset = next;
 }
}


/*
 * Dumps the content of a subset on screen. For debugging purposes only
 */
int
subset_dump(subset)
 struct subset * subset;
{
 int i;
 if(!subset)
  return(0);
 
 for(i=0;i<subset->num_fields;i++)
 {
 printf("%s,", subset->data[i]);
 }
 printf("\n");
 return subset_dump(subset->next);
}


/*
 * Returns the number of items in a subset
 */
int
subset_size(subset)
 struct subset * subset;
{
 int sz = 0;
 while(subset)
 {
  sz++;
  subset = subset -> next;
 }
 return sz;
}



/*---------------------------------------------------------------------*
 * Data mining functions                                               *
 *---------------------------------------------------------------------*/
 
 /*
  * We use a dumb SQL-like language to query our subsets. If a database
  * was to be linked, it should intercept these calls, rephrase them
  * and return the results as subsets.
  * 
  * The syntax is :
  *
  * SELECT <category [,category...]> FROM <table> [WHERE <category> = <value>
  [AND <category> = <value> ...]]
  *
  *
  * where <category> is one of :
  *  	. subnet
  *	. host
  *	. port
  *	. note	(security note)
  *	. warning (security warning)
  *	. hole  (security hole)
  *	. plugin id
  *
  * <select> may return multiple times the same entries. Hence it's wise
  * to use subset_uniq() on the output of a query.
  *
  *
  * Valid statements :
  *
  *	SELECT host FROM results WHERE subnet = '127.0.0'
  *	SELECT host,severity FROM results WHERE subnet = '127.0.0'
  *	SELECT host,severity,port FROM results WHERE subnet = '127.0.0'
  *
  *
  */
  

#define QUERY_TYPE_SUBNET 	1
#define	QUERY_TYPE_HOST	 	2
#define QUERY_TYPE_PORT	        3
#define QUERY_TYPE_PLUGIN_ID    4
#define QUERY_TYPE_SEVERITY	5
#define QUERY_TYPE_REPORT       6

#define QUERY_TYPE_TYPE	3
#define QUERY_TYPE_DATE	4


#define QUERY_TYPE_SUBNET_ASC 		"subnet"
#define QUERY_TYPE_HOST_ASC   		"host"
#define QUERY_TYPE_PORT_ASC   		"port"
#define QUERY_TYPE_PLUGIN_ID_ASC 	"plugin_id"
#define QUERY_TYPE_SEVERITY_ASC		"severity"
#define QUERY_TYPE_REPORT_ASC   	"report"
#define QUERY_TYPE_TYPE_ASC		"type"
#define QUERY_TYPE_DATE_ASC		"date"


#define QUERY_OP_AND		1
#define	QUERY_OP_OR		2

#define QUERY_OP_AND_ASC 	"AND"  



/* Maximum number of fields the user can ask for */
#define MAX_QUERIES 		20


struct condition {
	struct condition * next;
	int type;
	int operator;
	char value[1];
};  


struct query {
	char * table;
	int type[MAX_QUERIES];
	int num;
	int uniq;
	struct condition * conditions;
};


static u_short *
requests2lines(be, requests)
 int be;
 char * requests[BE_NUM_FIELDS];
{
 u_short * ret = emalloc(backends[be].num_lines*sizeof(u_short));
 int i;
 int max = 0;
 for(i=0;i<BE_NUM_FIELDS;i++)
 {
  if(requests[i])
  {
   struct field * f = backends[be].fields[i];
   max++;
   if(f)
   { 
    while(f)
    {
     if(!strcmp(f->value, requests[i]))
     {
      int j;
      for(j=0;j<f->num_lines;j++)
      {
      ret[f->lines[j]]++;
      }
      break;
     }
     f = f->next;
    }
   }
  }
 }
 
 for(i=0;i<backends[be].num_lines;i++)
 {
  if(ret[i] < max)ret[i] = 0;
 }
return ret;
}
 

static int
str2querytype(str)
 char * str;
{
 int type;

 if(!strcmp(str, QUERY_TYPE_SUBNET_ASC))
  type = QUERY_TYPE_SUBNET;
 else if(!strcmp(str, QUERY_TYPE_HOST_ASC))
   type = QUERY_TYPE_HOST;
 else if(!strcmp(str, QUERY_TYPE_PORT_ASC))
   type = QUERY_TYPE_PORT;
 else if(!strcmp(str, QUERY_TYPE_PLUGIN_ID_ASC))
   type = QUERY_TYPE_PLUGIN_ID;
 else if(!strcmp(str, QUERY_TYPE_SEVERITY_ASC))
    type = QUERY_TYPE_SEVERITY;
 else if(!strcmp(str, QUERY_TYPE_REPORT_ASC))
    type = QUERY_TYPE_REPORT;
 else if(!strcmp(str, QUERY_TYPE_TYPE_ASC))
 	type = QUERY_TYPE_TYPE;
 else if(!strcmp(str, QUERY_TYPE_DATE_ASC))
 	type = QUERY_TYPE_DATE;
 else	
    type = -1;
   
  return type;
}	 

static int
str2querytypes(str, query)
 char * str;
 struct query * query;
{
 char * t;
 query->num = 0;
 
 while(str)
 {
  int type;
  t = strchr(str, ',');
  if(t)t[0] = '\0';
  type = str2querytype(str);
  if(type < 0)
   return type;
  query->type[query->num++] = type;
  if(!t)str = NULL;
  else str = &(t[1]);
 }
 return 0;
}

static int
str2querycondition(str)
 char * str;
{
 if(!strcmp(str, QUERY_OP_AND_ASC))
   return QUERY_OP_AND;
 else return -1;
}
	

/*
 * Parses the condition(s) of a query (the whole part
 * after 'where')
 */
static struct condition *
compile_conditions(str)
 char * str;
{
 struct condition * ret = NULL;
 int operator = QUERY_OP_AND;
 for(;;)
 {
  int type = 0;
  char * t;
  struct condition * condition;
 
  if(!str || (str[0] == '\0'))
   break;
  
  while(str[0]==' ')
    str++;
  
  t = &(str[1]);
  while(t[0]!='=' &&
        t[0])
	{
	 if(t[0]==' ')t[0]='\0';
	 t++;
	}
	
  if(!t[0])
  {
   fprintf(stderr, "Garbage in the conditions\n");
   return (void*)-1;
  }
  
 
  type = str2querytype(str);
  str = &(t[1]);
  while(str[0]==' ')str++;
  if(str[0] != '\'')
  {
   fprintf(stderr, "Syntax error in query conditions - missing quote\n");
   return (struct condition*)-1;
  }
  str++;
  t = str;
  while((t[0]!='\'')  &&
        (t[0]))t++;
	
  if(!t[0])
  {
   fprintf(stderr, "Syntax error in query conditions - missing closing quote\n");
   return (struct condition*)-1;
  }
  t[0] = '\0';

  condition = emalloc(sizeof(*condition) + strlen(str) + 1);
  condition->operator = operator;
  condition->type = type;
  memcpy(condition->value, str, strlen(str));
  condition->next = ret;
  ret = condition;
  str  = &(t[1]);
  
  /*
   * Trailing data - probably the next operator
   */
  if(str[0])
  {
   while(str[0]==' ' &&
         str[0])str++;
	 
   if(str[0])
   {
     t = &(str[1]);
     while(t[0]!=' ' && 
           t[0])t++;
     if(!t[0])
     {
      fprintf(stderr, "Trailing garbage in query - '%s'\n", str);
      return (void*)-1;
     }
     t[0] = '\0';
     operator = str2querycondition(str);
     str = &(t[1]);
    } 	   
  }
 }
 return ret;
}

static struct query * 
compile_query(str)
 char * str;
{
 struct query * ret;
 char * a, * b;
 int type = -1;
 int uniq = 0;

 if(strncmp(str, "SELECT ", strlen("SELECT ")))
  {
   fprintf(stderr, "Bad query : expected <SELECT >.\n");
   return NULL;
  }
 else
   str+=strlen("SELECT ");
   
 while(str[0] == ' ')
   str++;
 a = strchr(str, ' ');
 if(a)a[0]='\0';
 
 ret = emalloc(sizeof(*ret));
 ret->type[0] = type;
 ret->num  = 1;
 type = str2querytypes(str, ret);

 if(type < 0)
 {
  efree(&ret);
  fprintf(stderr, "'%s' - bad query type\n", str);
  return NULL;
 }
 
 
 
 if(!a)
 {
  fprintf(stderr, "'%s' - table not specified\n", str);
  efree(&ret);
  return NULL;
 }
 else
 {
  a++;
  if(strncmp(a, "FROM ", strlen("FROM ")))
  {
   fprintf(stderr, "'%s' - \"FROM\" expected in '%s'\n", a, str);
   efree(&ret);
   return NULL;
  }
  a+=strlen("FROM ");
  ret->table = a;
  a = strchr(a, ' ');
  if(a)a[0] = '\0';
  ret->table = estrdup(ret->table); 
 }
 
 
 
 ret->uniq = uniq;
 if(a)
 {
  a++;
  while(a[0]==' ')a++;
  b = strchr(a, ' ');
  if(!b)
  {
   fprintf(stderr, "Garbage after query\n");
   efree(&ret);
   return NULL;
  }
  b[0]='\0';
  
  if(strcmp(a, "WHERE"))
  {
   fprintf(stderr, "Bad keyword after query ('%s')\n", a);
   efree(&ret);
   return NULL;
  }
  b = &(b[1]);
  ret->conditions = compile_conditions(b); 
  if(ret->conditions == (void*)-1)
   return NULL;
 }
 return ret;
}

static void
free_query(query)
 struct query * query;
{
 struct condition * conditions = query->conditions;
 while(conditions)
 {
  struct condition * next = conditions->next;
  efree(&conditions);
  conditions = next;
 }
 efree(&query);
}




/*
 * parse a line in our .nsr file and returns the records
 * contained in it
 */
static int
__split_line(entry, table, subnet,  hostname, port, plugin_id, severity, data)
 char * entry;
 char ** table, **subnet, **hostname, ** port, ** plugin_id, ** severity, ** data;
{
 char * t;
 *port = *plugin_id = *severity = *data = NULL;
 
 *table = entry;
 t = strchr(entry, '|');
 if(t)
  t[0] = '\0';
 else
  return 0;
 
 entry = &(t[1]);  
 *subnet = entry;
 t = strchr(entry, '|');
 if(t)
  t[0] = '\0';
 else 
  return 0;
  
   
 entry = &(t[1]);  
 *hostname = entry;
 t = strchr(entry, '|');
 if(t)
  t[0] = '\0';
 else 
  return 0;
 
 entry = &(t[1]);
 *port = entry;
 t = strchr(entry, '|');
 if(t)
  t[0] = '\0';
 else
  return 0;
 
 entry = &(t[1]);
 *plugin_id = entry;
 t = strchr(entry, '|');
 if(t) 
  t[0] = '\0';
 else
  return 0;
 
 entry = &(t[1]);
 *severity = entry;
 if(t)
  t[0] = '\0';
 else
  return 0;
 
 t = strchr(entry, '|');
 if(t) 
  t[0] = '\0';
 else
  return 0;
  
 entry = &(t[1]);
 *data = entry;

#if 1
 if(entry)
 {
  char * t = strchr(entry, ';');
  while(t)
  {
   t[0] = '\n';
   t = strchr(t+1, ';');
  }
 }
#endif
 
 return 0;
}






/*
 * Executes a compiled query and returns the result as a subset.
 *
 * This is god damn ugly and you probably want to use a real
 * sql backend if you want performances
 *
 */
 

static struct subset * 
execute_query_flatfile(be, query)
 int be;
 struct query * query;
{
 struct subset * ret = NULL;
 static char buf[1048576];
#ifdef HAVE_MMAP
 if(backends[be].mmap) backends[be].cur_line = 0;
 else
#endif 
 if(lseek(backends[be].fd, 0, SEEK_SET) < 0)
 {
  perror("lseek ");
 }
 
#ifdef HAVE_MMAP 
 if(backends[be].fields)
 {
  char * requests[BE_NUM_FIELDS];
  u_short * lines;
  struct condition * conditions = query->conditions;
  int i;
  bzero(requests, sizeof(*requests)*BE_NUM_FIELDS);
  requests[0] = query->table;
  while(conditions)
  {
   requests[conditions->type] = conditions->value;
   conditions = conditions->next;
  }
  lines = requests2lines(be, requests);
  for(i=0;i<backends[be].num_lines;i++)
  {
   if(lines[i])
   { 
   int j;
   char * val = NULL;
   char buf[1048576];
   char * table;
   char * subnet;
   char * hostname;
   char * port;
   char * plugin_id;
   char * severity;
   char * data;
   mmap_read_line_n(be, buf, sizeof(buf), i);
   __split_line(buf, &table, &subnet, &hostname, &port, &plugin_id, &severity, &data);
   for(j=0;j<query->num;j++)
   {
   switch(query->type[j])
   {
    case QUERY_TYPE_SUBNET :
        val = subnet;
	break;
    case QUERY_TYPE_HOST :
    	val = hostname;
	break;
    case QUERY_TYPE_PORT :
     	val =  port;
	break;
    case QUERY_TYPE_PLUGIN_ID :
        val = plugin_id;
	break;
    case QUERY_TYPE_SEVERITY :
        val = severity;
	break;	 
   case QUERY_TYPE_REPORT :
         val = data;
	 break;
    default:
    	fprintf(stderr, "data_mining.c: invalid switch value\n");
	break;
	
   }
   if(val)
    {
       if(!j) ret = subset_add(ret, val);
       else ret = subset_add_again(ret,val);
     }
    }
   }
  }
  efree(&lines);
  return ret;
 }
#endif 
 while(read_line(be,buf, sizeof(buf)) > 0)
 {
  char * table;
  char * subnet;
  char * hostname;
  char * port;
  char * plugin_id;
  char * severity;
  char * data;
  int selected = 0;
  struct condition * conditions = query->conditions;
  __split_line(buf, &table, &subnet, &hostname, &port, &plugin_id, &severity, &data);
 
 
  if(strcmp(table, query->table))
   continue;
  if(!conditions)
   selected = 1;
  else 
   while(conditions)
   {
    char * candidate = NULL;
    switch(conditions->type)
    {
     case QUERY_TYPE_SUBNET :
        candidate = subnet;
	break;
     case QUERY_TYPE_HOST :
     	candidate = hostname;
	break;	
     case QUERY_TYPE_PORT :
      	candidate = port;
	break;
     case QUERY_TYPE_PLUGIN_ID :
     	candidate = plugin_id;
	break;
     case QUERY_TYPE_SEVERITY :
        candidate = severity;
	break;	
    
     case QUERY_TYPE_REPORT :
       candidate = data;
       break;
    }
  
       if(candidate &&
       !strcmp(candidate, conditions->value))
        {
       	selected = 1; 
	}	   
	else if(conditions->operator == QUERY_OP_AND)
	 {
	   selected = 0;
	   break;
	 }
	 
   conditions  = conditions->next;		       	
  }
  

  if(selected)
  {
   int i;
   char * val = NULL;
 
   for(i=0;i<query->num;i++)
   {
   switch(query->type[i])
   {
    case QUERY_TYPE_SUBNET :
        val = subnet;
	break;
    case QUERY_TYPE_HOST :
    	val = hostname;
	break;
    case QUERY_TYPE_PORT :
     	val =  port;
	break;
    case QUERY_TYPE_PLUGIN_ID :
        val = plugin_id;
	break;
    case QUERY_TYPE_SEVERITY :
         val = severity;
	break;	 
   case QUERY_TYPE_REPORT :
         val = data;
	 break;
	
   }
   if( (i == 0) &&
       (val == NULL)
     )
      {
       	goto continue_loop;
      }
   if(val)
    {
     if(query->uniq)
     {
      if(!i)
      {
       if(subset_in(ret, val)) 
         {
      	 goto continue_loop;
	 }
       else
        ret = subset_add(ret, val);
      }
      else ret = subset_add_again(ret, val);
     }	
     else
      {
       if(!i) ret = subset_add(ret, val);
       else ret = subset_add_again(ret, val);
      }
     }
    }
   }
   continue;
continue_loop :
   ;
  }
  return ret;
}


struct subset  *
query_backend(int be,char* str, ...)
{
 struct query * query;
 struct subset * ret;
 va_list param;
 int sz = 8192;
 int r;
 char * ptr = emalloc(sz);
 va_start(param, str);

  for(;;)
  {
   r = vsnprintf(ptr, sz, str, param);
   if(r >= 0 && r < sz)break;
   sz = r > sz ? r + 1 : sz * 2;
   ptr = realloc(ptr, sz);
  }


 query = compile_query(ptr);

 va_end(param);
 efree(&ptr);
 
 if(!query)
  return NULL;
  
  
 ret = execute_query_flatfile(be, query);
 free_query(query);
 return ret;
}
