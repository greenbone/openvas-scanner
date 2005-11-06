#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char * NESSUS_KEYFILE = 0;
char * NESSUS_RCFILE  = 0;

int init_directories() {
	char *buf;
	char * e = getenv("NESSUS_HOME");
	

	if(!e) {
		fprintf(stderr, "NESSUS_HOME is not set\n");
		return -1;
	}
	buf = (char *) malloc(4096);
	sprintf(buf, "%s/nessus.keys", e);
	NESSUS_KEYFILE = strdup(buf);
	sprintf(buf, "%s/nessusrc", e);
	NESSUS_RCFILE = strdup(e);
	free(buf);
	return 0;
}

