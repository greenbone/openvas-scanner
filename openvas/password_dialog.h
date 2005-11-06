#ifndef _NESSUSC_PASSWORD_DIALOG_H
#define _NESSUSC_PASSWORD_DIALOG_H

#define CHANGE_PWD_BLURB "\n\
   Enter your new passphrase.\n\n"

char * pass_dialog (int);
char * cmdline_pass (int);
char * get_pwd (int);
int created_private_key (void) ;
char * keypass_dialog(int);

#endif
