#ifndef PLUGINS_REQUIREMENTS_H__
#define PLUGINS_REQUIREMENTS_H__

char * requirements_plugin(struct kb_item **, 
                           struct scheduler_plugin *, 
			   struct arglist *);
 

struct arglist*  requirements_common_ports(struct scheduler_plugin *, struct scheduler_plugin *);
			       
#endif			  
