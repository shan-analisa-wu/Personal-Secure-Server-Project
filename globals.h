/*
 * Declarations of various global variables.
 */
#include <stdbool.h>

extern char *server_root;
extern bool silent_mode;
extern int token_expiration_time;
extern bool html5_fallback;
extern int accepting_socket;

extern int create_listen_thread(pthread_t *th, int listensocket);
extern char server_root_real[1024];
extern void* do_http_handle(void *args);
extern void* do_listen_and_accept(void* args);

