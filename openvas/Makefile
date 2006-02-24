include ../nessus.tmpl

INCLUDE = ${include}
LIBS = `$(NESSUSCONFIG) --libs` $(X_LIBS) $(X_CFLAGS) \
	$(RUN_LIBS) $(C_R_LIB) -lm -lgdc

NESSUS_INCLUDE=`sh ./cflags`	

OBJS = auth.o \
       comm.o \
       sighand.o \
       xstuff.o \
       cli.o \
       parser.o \
       plugin_infos.o \
       preferences.o \
       families.o \
       attack.o \
       report.o \
       report_ng.o \
       report_save.o \
       report_utils.o \
       nsr_output.o  \
       nbe_output.o \
       html_output.o \
       latex_output.o \
       text_output.o \
       xml_output.o \
       xml_output_ng.o \
       html_graph_output.o \
       error_dialog.o \
       password_dialog.o \
       monitor_dialog.o \
       backend.o \
       data_mining.o \
       netmap.o \
       detached_index.o \
       read_target_file.o \
       regex.o \
       filter.o \
       dirutils.o \
       sslui.o \
       nessus.o 
       

all : cflags ${make_bindir}/nessus


${make_bindir}/nessus : cflags nessus
	test -d ${make_bindir} || mkdir ${make_bindir}
	cp nessus ${make_bindir}

        
cflags : 
	@echo "$(NESSUS_CFLAGS) $(NESSUS_DEFS) $(INCLUDE)"  | sed 's/\"/\\\"/g' > cflags.tmp
	@echo "echo \"`cat cflags.tmp`\"" > cflags
	@rm cflags.tmp
	@chmod +x cflags

nessus : cflags $(OBJS) 
	$(CC) $(LDFLAGS) $(OBJS)   -o nessus $(LIBS) 

detached_index.o : cflags detached_index.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c detached_index.c

preferences.o : cflags preferences.c preferences.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c preferences.c 

error_dialog.o : cflags error_dialog.c error_dialog.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c error_dialog.c 

families.o : cflags families.c families.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c families.c 

plugin_infos.o : cflags plugin_infos.c plugin_infos.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c plugin_infos.c 

main_window.o : cflags main_window.c main_window.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c main_window.c 

nsr_output.o : cflags nsr_output.c nsr_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nsr_output.c 

nbe_output.o : cflags nbe_output.c nbe_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nbe_output.c 
	
	
html_output.o : cflags html_output.c html_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c html_output.c 

text_output.o : cflags text_output.c text_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c text_output.c 

xml_output.o : cflags xml_output.c xml_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c xml_output.c

xml_output_ng.o : cflags xml_output_ng.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c xml_output_ng.c

latex_output.o : cflags latex_output.c latex_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c latex_output.c 

html_graph_output.o : cflags html_graph_output.c html_graph_output.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c html_graph_output.c 


monitor_dialog.o : cflags monitor_dialog.c monitor_dialog.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c monitor_dialog.c 
	
backend.o : cflags backend.c backend.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c backend.c 	

data_mining.o : cflags data_mining.c data_mining.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c data_mining.c 	
	
	
report_utils.o : cflags report_utils.h report_utils.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c report_utils.c 
nessus.o : cflags nessus.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c nessus.c 

sighand.o : cflags sighand.c sighand.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c sighand.c 

auth.o : cflags auth.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c auth.c 

comm.o : cflags comm.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c comm.c 

report.o : cflags report.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c report.c 

report_ng.o : cflags report_ng.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c report_ng.c 
	
report_save.o : cflags report_save.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c report_save.c 	
	
	
parser.o : cflags parser.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c parser.c 

attack.o : cflags attack.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c attack.c 

password_dialog.o : cflags password_dialog.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c password_dialog.c 
xstuff.o : cflags xstuff.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c xstuff.c 
cli.o : cflags cli.c cli.h
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c cli.c
read_target_file.o : cflags read_target_file.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c read_target_file.c 


netmap.o : cflags netmap.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c netmap.c 

regex.o : cflags regex.c 
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c regex.c 
	
filter.o : cflags filter.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c filter.c 
	
	
dirutils.o : cflags dirutils.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c dirutils.c

sslui.o : cflags sslui.c
	$(CC) $(CFLAGS) $(NESSUS_INCLUDE) -c sslui.c
					
gdchart0.94b/gdc.o : cflags
	cd gdchart0.94b && $(MAKE)

gdchart0.94b/gdchart.o : cflags
	cd gdchart0.94b && $(MAKE)

gdchart0.94b/price_conv.o : cflags
	cd gdchart0.94b && $(MAKE)

gdchart0.94b/gdc_pie.o : cflags
	cd gdchart0.94b && $(MAKE)
clean : 
	rm -f *.o nessus *~ cflags prefs_dialog/*.o
	cd gdchart0.94b && $(MAKE) clean
