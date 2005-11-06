

include ../nessus.tmpl

all: nessus-fetch

nessus-fetch: nessus-fetch.o
	$(CC) nessus-fetch.o -o nessus-fetch $(LIBS)

nessus-fetch.o: nessus-fetch.c
	$(CC) $(NESSUS_CFLAGS) ${include} $(DEFS) $(NESSUS_DEFS) -c nessus-fetch.c

clean:
	rm -f nessus-fetch nessus-fetch.o
