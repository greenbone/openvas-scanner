#ifndef __DATA_MINING_H__
#define __DATA_MINING_H__



/*---------------------------------------------------------------*
 * Subset management  						 *
 *---------------------------------------------------------------*/
 
struct subset 
{
   struct subset * next;
   int num_fields;
   char ** data;
};

/* Comparison function for subset_sort() */
typedef int(*cmp_func_t)(char*, char*);




struct subset * subset_next(struct subset*);
char * subset_value(struct subset*);
char * subset_nth_value(struct subset *, int);
int subset_num_values(struct subset*);
int subset_size(struct subset*);
void subset_free(struct subset *);



struct subset * subset_sort(struct subset *, int, int, cmp_func_t*);
struct subset * subset_uniq(struct subset * , int);

struct subset * query_backend(int, char *, ...);


#endif
