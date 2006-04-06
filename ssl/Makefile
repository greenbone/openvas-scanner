include ../openvas.tmpl


OBJS = openvas-mkrand.o 

all : openvas-mkrand

openvas-mkrand: $(OBJS)
	$(CC) $(OBJS) -o openvas-mkrand -lm

openvas-mkrand.o: openvas-mkrand.c
	$(CC) $(CFLAGS) -c openvas-mkrand.c 

clean : 
	rm -f *.o openvas-mkrand
