#ifndef PREFS_KB_H__
#define PREFS_KB_H__

#ifdef ENABLE_SAVE_KB

void prefs_dialog_kb_get_prefs(struct arglist*);
void prefs_dialog_kb_set_prefs(struct arglist *, struct arglist *);
struct arglist * prefs_dialog_kb();

#endif
#endif
