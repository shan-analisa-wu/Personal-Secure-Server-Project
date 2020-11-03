/*
 * Skeleton files for personal server assignment.
 *
 * @author Godmar Back
 * written for CS3214, Spring 2018.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "buffer.h"
#include "hexdump.h"
#include "http.h"
#include "socket.h"
#include "bufio.h"
#include "globals.h"

/* Implement HTML5 fallback.
 * This means that if a non-API path refers to a file and that
 * file is not found or is a directory, return /index.html
 * instead.  Otherwise, return the file.
 */
bool html5_fallback = false;
bool silent_mode = false;
int token_expiration_time = 24 * 60 * 60;   // default token expiration time is 1 day
int accepting_socket;
jwtmgr *jwtlib;



static void
usage(char * av0)
{
    fprintf(stderr, "Usage: %s [-p port] [-R rootdir] [-h] [-e seconds]\n"
                    "  -p port      port number to bind to\n"
                    "  -R rootdir   root directory from which to serve files\n"
                    "  -e seconds   expiration time for tokens in seconds\n"
                    "  -h           display this help\n"
            , av0);
    exit(EXIT_FAILURE);
}

int
main(int ac, char *av[])
{
    int opt;
    char *port_string = NULL;
    pthread_t listenth;
    char dirbuff[1024];
    server_root = NULL;
    while ((opt = getopt(ac, av, "ahp:R:se:")) != -1) {
        switch (opt) {
            case 'a':
                html5_fallback = true;
                break;

            case 'p':
                port_string = optarg;
                break;

            case 'e':
                token_expiration_time = atoi(optarg);
                fprintf(stderr, "token expiration time is %d\n", token_expiration_time);
                break;

            case 's':
                silent_mode = true;
                break;

            case 'R':
                server_root = optarg;
                break;

            case 'h':
            default:    /* '?' */
                usage(av[0]);
        }
    }

    if (server_root == NULL)
    {
        fprintf(stderr, "No setting work dir，exit\n");
        exit(EXIT_FAILURE);
    }

    if (port_string == NULL)
    {
        fprintf(stderr, "No setting server port，exit\n");
        exit(EXIT_FAILURE);
    }

    // initialize jwt library
    jwtlib = jwtmgr_create_and_init(0, "wusansan");

    char *p = getcwd(dirbuff, sizeof(dirbuff));
    fprintf(stderr, "current work path: %s\n", p);
    if (realpath(server_root, server_root_real) == NULL)
    {
        fprintf(stderr, "server root dir not a valid dir:%s\n", server_root);
        exit(EXIT_FAILURE);
    }

    if (strcmp(p, server_root_real))
    {
        if (chdir(server_root_real) < 0)
        {
            fprintf(stderr, "chanage work dir failed, please check dir exits or not and permit. dir:%s\n", server_root_real);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "chanage work dir to: %s\n", server_root_real);
    }
    server_root = &server_root_real[0];
    fprintf(stderr, "Using port %s\n", port_string);
    accepting_socket = socket_open_bind_listen(port_string, 1024);
    if (accepting_socket == -1)
    {
        fprintf(stderr, "create listen socket error %s\n", port_string);
        exit(EXIT_SUCCESS);
    }

    if (create_listen_thread(&listenth, accepting_socket) == 0)
    {
        pthread_join(listenth, NULL);
    }
    else
    {
        fprintf(stderr, "listen error %s\n", port_string);
    }

    exit(EXIT_SUCCESS);
}

