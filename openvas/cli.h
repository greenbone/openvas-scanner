#ifndef __CLI_H__
#define __CLI_H__

typedef char*(*cli_auth_pwd_t)(int);
typedef int (*output_func_t)(struct arglist *, char *);

 
struct cli_args {
	char * server;
	int    port;
	char * login;
	char * password;
	char * cipher;
	char * target;
	char * results;
	char * extension;
	int  interactive;
	cli_auth_pwd_t auth_pwd;
	output_func_t output;
	int backend;
	int verbose;
	int backend_output_func;
	harglst * plugins_order_table;
	};
	
struct cli_args * cli_args_new();
void cli_args_server(struct cli_args *, char*);
void cli_args_port(struct cli_args *,int);

void cli_args_login(struct cli_args *,char*);
void cli_args_password(struct cli_args *,char*);

void cli_args_auth_pwd(struct cli_args*, cli_auth_pwd_t);

void cli_args_target(struct cli_args *,char*);
void cli_args_results(struct cli_args *,char*);

void cli_args_output(struct cli_args *, char* type);

void cli_args_cipher(struct cli_args *,char*);

int cli_connect_to_nessusd(struct cli_args*);

int cli_test_network(struct cli_args*);
void cli_report(struct cli_args*);

void cli_dump_plugins(struct cli_args*);
void cli_dump_prefs(struct cli_args*);

void cli_sql_dump_plugins(struct cli_args*);
void cli_sql_dump_prefs(struct cli_args*);
void cli_args_verbose(struct cli_args*, int);
#ifdef ENABLE_SAVE_TESTS
void cli_restore_session(struct cli_args *, char *);
void cli_list_sessions(struct cli_args *);
#endif

int cli_close_connection(struct cli_args*);
#endif
