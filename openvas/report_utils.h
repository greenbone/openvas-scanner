#ifndef NESSUSC_REPORT_UTILS_H__
#define NESSUSC_REPORT_UTILS_H__

struct arglist * sort_by_port(struct arglist *);
 
int arglist_length(struct arglist *);

int number_of_notes_by_port(struct arglist *);
int number_of_notes_by_host(struct arglist * );

int number_of_warnings_by_port(struct arglist *);
int number_of_warnings_by_host(struct arglist * );

int number_of_holes_by_port(struct arglist *);
int number_of_holes_by_host(struct arglist *);

int number_of_notes(struct arglist * );
int number_of_warnings(struct arglist * );
int number_of_holes(struct arglist * );

struct arglist *most_dangerous_host(struct arglist *);
struct arglist * sort_dangerous_hosts(struct arglist *);

int safe_strcmp(char*, char*);
#endif
