#ifndef NESSUS_READ_TARGET_FILE_H__
#define NESSUS_READ_TARGER_FILE_H__
void target_file_select();
#ifdef USE_GTK
void read_target_file(GtkWidget *, GtkWidget*);
#endif
char * target_file_to_list(char *);
char* target_translate(char*);

#endif
