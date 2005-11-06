#ifndef __NESSUS_FILTER_H__
#define __NESSUS_FILTER_H__
struct plugin_filter {
	char * pattern;
	int filter_on_name:1;
	int filter_on_description:1;
	int filter_on_summary:1;
	int filter_on_author:1;
	int filter_on_category:1;
	int filter_on_cve:1;
	int filter_on_bid:1;
	int filter_on_xref:1;
	int filter_on_id;
};
	
int ask_filter(struct plugin_filter*);

int filter_plugin(struct plugin_filter *, struct arglist*);
#endif
