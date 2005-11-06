#ifndef _NESSUSC_PREFS_DIALOG_PLUGINS_PREFS_H
#define _NESSUSC_PREFS_DIALOG_PLUGINS_PREFS_H
struct arglist * prefs_dialog_plugins_prefs();
int prefs_plugins_prefs_redraw(GtkWidget *, void *, struct arglist *);
void prefs_plugins_reset(struct arglist *, struct arglist *, struct arglist*);
#endif
