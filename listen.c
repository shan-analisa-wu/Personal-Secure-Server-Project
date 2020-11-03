
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>
#include "buffer.h"
#include "hexdump.h"
#include "http.h"
#include "socket.h"
#include "bufio.h"
#include "globals.h"

extern jwtmgr *jwtlib;

/**
 * Handle http transaction
 * @param args The socket number
 */
void*  do_http_handle(void *args)
{
    int ret;
    int *sock = (int *)args;
    struct http_client *client = (struct http_client *)malloc(sizeof(struct http_client));
    memset(client, 0, sizeof(struct http_client));
    struct http_transaction *ta = (struct http_transaction *)malloc(sizeof(struct http_transaction));

    http_setup_client(client, bufio_create(*sock));
    while (1)
    {
        memset(ta, 0, sizeof(struct http_transaction));

        ta->jwt = jwtlib;

        // handle http request
        ret = http_handle_transaction(ta, client);

        // free the memory in ta
        http_transaction_clean(ta);

        if (ret == false)
        {
            break;
        }

        // Check if we need to close connection
        if (ta->IsKeepAlive != 1)
        {
            break;
        }
    }

    bufio_close(client->bufio);
    free(client);
    free(ta);
    free(sock);
    return NULL;
}

/**
 * A thread to listen request and accept request
 * @param args The socket number
 * @return
 */
void* do_listen_and_accept(void* args)
{
    pthread_t th;
    int sock = accepting_socket;

    while(1)
    {
        int *pdatasock = (int *)malloc(sizeof(int));
        int client_socket = socket_accept_client(sock);
        *pdatasock = client_socket;

        if (client_socket == -1)
        {
            fprintf(stderr, "socket accept failed\n");
            break;
        }

        // create new thread to handle http transaction
        pthread_create(&th, NULL, do_http_handle, pdatasock);
    }

    return NULL;
}

int create_listen_thread(pthread_t *thhander, int listensocket)
{
    int ret;
    ret = pthread_create(thhander, NULL, do_listen_and_accept, &listensocket);

    if (ret != 0)
    {
        printf("Create thread error!\n");
        return -1;
    }
    return 0;
}