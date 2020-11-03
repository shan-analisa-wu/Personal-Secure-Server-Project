/*
 * Quick demo of how to use libjwt using a HS256.
 *
 * @author gback, CS 3214, Spring 2018
 */
#include <jwt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char * NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";

int
main()
{
    jwt_t *mytoken;

    if (jwt_new(&mytoken))
        perror("jwt_new"), exit(-1);

    if (jwt_add_grant(mytoken, "sub", "user0"))
        perror("jwt_add_grant sub"), exit(-1);

    time_t now = time(NULL);
    if (jwt_add_grant_int(mytoken, "iat", now))
        perror("jwt_add_grant iat"), exit(-1);

    if (jwt_add_grant_int(mytoken, "exp", now + 3600 * 24))
        perror("jwt_add_grant exp"), exit(-1);

    if (jwt_set_alg(mytoken, JWT_ALG_HS256, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, strlen(NEVER_EMBED_A_SECRET_IN_CODE)))
        perror("jwt_set_alg"), exit(-1);

    printf("dump:\n");
    if (jwt_dump_fp(mytoken, stdout, 1))
        perror("jwt_dump_fp"), exit(-1);

    char *encoded = jwt_encode_str(mytoken);
    if (encoded == NULL)
        perror("jwt_encode_str"), exit(-1);

    printf("encoded as %s\nTry entering this at jwt.io\n", encoded);

    jwt_t *ymtoken;
    if (jwt_decode(&ymtoken, encoded, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, strlen(NEVER_EMBED_A_SECRET_IN_CODE)))
        perror("jwt_decode"), exit(-1);

    char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
    if (grants == NULL)
        perror("jwt_get_grants_json"), exit(-1);

    printf("redecoded: %s\n", grants);
}
