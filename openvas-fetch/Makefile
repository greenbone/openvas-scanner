

include ../nessus.tmpl

all: openvas-fetch

openvas-fetch: openvas-fetch.o
	$(CC) openvas-fetch.o -o openvas-fetch $(LIBS)

openvas-fetch.o: openvas-fetch.c
	$(CC) $(NESSUS_CFLAGS) ${include} $(DEFS) $(NESSUS_DEFS) -c openvas-fetch.c

clean:
	rm -f openvas-fetch openvas-fetch.o
