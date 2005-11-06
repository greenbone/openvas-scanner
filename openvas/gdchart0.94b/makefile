include ../../nessus.tmpl
GDC_INCL = .
GD_INCL  = gd1.3
GD_LIB   = gd1.3
IINCL    = $(CFLAGS) `sh ../cflags`



all: gdc.o gdchart.o price_conv.o gdc_pie.o $(GD_LIB)/libgd.a

# compile the samples
gdc_samp1: gdc.o gdchart.o price_conv.o gdc_samp1.o $(GD_LIB)/libgd.a
	$(CC) -o gdc_samp1 gdc.o gdchart.o price_conv.o gdc_samp1.o -L$(GD_LIB) -lgd -lm

gdc_samp1.o: $(GDC_INCL)/gdc.h $(GDC_INCL)/gdchart.h gdc_samp1.c
	$(CC) $(IINCL) -I$(GDC_INCL) -c gdc_samp1.c

gdc_samp2: gdc.o gdchart.o price_conv.o gdc_samp2.o $(GD_LIB)/libgd.a
	$(CC) $(IINCL) -o gdc_samp2 gdc.o gdchart.o price_conv.o gdc_samp2.o -L$(GD_LIB) -lgd -lm

gdc_samp2.o: $(GDC_INCL)/gdc.h $(GDC_INCL)/gdchart.h gdc_samp2.c
	$(CC) $(IINCL) -I$(GDC_INCL) -c gdc_samp2.c

gdc_pie_samp: gdc.o gdc_pie.o price_conv.o gdc_pie_samp.o $(GD_LIB)/libgd.a
	$(CC) $(IINCL) -o gdc_pie_samp gdc.o gdc_pie.o price_conv.o gdc_pie_samp.o -L$(GD_LIB) -lgd -lm

gdc_pie_samp.o: $(GDC_INCL)/gdc.h $(GDC_INCL)/gdcpie.h gdc_pie_samp.c
	$(CC) $(IINCL) -I$(GDC_INCL) -c gdc_pie_samp.c

# --- compile the lib ---
price_conv.o: price_conv.c
	$(CC) $(IINCL) -I$(GD_INCL) -I$(GDC_INCL) -c price_conv.c

gdc.o: gdc.c gdc.h
	$(CC) $(IINCL) -I$(GD_INCL) -I$(GDC_INCL) -c gdc.c

gdc_pie.o: $(GDC_INCL)/gdc.h $(GDC_INCL)/gdcpie.h gdc_pie.c
	$(CC) $(IINCL) -I$(GD_INCL) -I$(GDC_INCL) -c gdc_pie.c

gdchart.o: $(GDC_INCL)/gdc.h $(GDC_INCL)/gdchart.h gdchart.c
	$(CC) $(IINCL) -I$(GD_INCL) -I$(GDC_INCL) -c gdchart.c

$(GD_LIB)/libgd.a:
	cd $(GD_LIB) ; $(MAKE) -f Makefile libgd.a

# --- clean ---
clean:
	rm -f *.o gdc_samp1 gdc_samp2 gdc_pie_samp
	cd $(GD_LIB) ; $(MAKE) -f Makefile clean

