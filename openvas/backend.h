#ifndef __BACKEND_H__
#define __BACKEND_H__



#define BACKEND_NSR 1


#define BE_NUM_FIELDS 7


#ifdef HAVE_MMAP
struct field {
	char *value;
	int * lines;
	int num_lines;
	int allocated_lines;
	struct field * next;
};
#endif



	
struct backend {
	int fd; 
	char * fname;
	int  backend_type;
	int  disposable;
#ifdef HAVE_MMAP	
	char * mmap;
	int mmap_attempts;
	char ** lines;
	char ** eols;
	struct field ** fields;
	int num_lines;
	int cur_line;
#endif
	};
	
	
int backend_init(char *);


int backend_insert_report_data(int, char*, char*,char*,char*,char*,char*);
int backend_insert_report_port(int, char*, char*, char*);
int backend_insert_timestamps(int, char*, char*, char*);

int backend_type(int);

int backend_close(int);
int backend_dispose(int);
int backend_empty(int);
int backend_clear_all();

int backend_fd(int);

int backend_import_report(char*);
struct arglist * backend_convert(int);

#endif
