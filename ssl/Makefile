include ../nessus.tmpl


OBJS = nessus-mkrand.o 

all : nessus-mkrand

nessus-mkrand: $(OBJS)
	$(CC) $(OBJS) -o nessus-mkrand -lm

nessus-mkrand.o: nessus-mkrand.c
	$(CC) $(CFLAGS) -c nessus-mkrand.c 

clean : 
	rm -f *.o nessus-mkrand
