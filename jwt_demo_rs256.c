/*
 * Quick demo of how to use libjwt using a RS256.
 * You must have created a private/public key pair like so:
 *
 *  openssl genpkey -algorithm RSA -out myprivatekey.pem -pkeyopt rsa_keygen_bits:2048
 *  openssl rsa -in myprivatekey.pem -pubout > mykey.pub
 *
 * @author gback, CS 3214, Spring 2018
 */
#include <jwt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

unsigned char private_key[16384];
unsigned char public_key[16384];

static void 
read_key(unsigned char *key, const char *name)
{
    FILE *f = fopen(name, "r");
    if (f == NULL)
        perror("fopen"), exit(-1);
    size_t len = fread(key, 1, 8192, f);
    key[len] = '\0';
    fclose(f);
}

int
main()
{
    read_key(private_key, "myprivatekey.pem");
    read_key(public_key, "mykey.pub");

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

    if (jwt_set_alg(mytoken, JWT_ALG_RS256, 
            private_key, strlen((char *)private_key)))
        perror("jwt_set_alg"), exit(-1);

    printf("dump:\n");
    if (jwt_dump_fp(mytoken, stdout, 1))
        perror("jwt_dump_fp"), exit(-1);

    char *encoded = jwt_encode_str(mytoken);
    if (encoded == NULL)
        perror("jwt_encode_str"), exit(-1);

    printf("encoded as %s\nTry entering this at jwt.io\n", encoded);

    jwt_t *ymtoken;
    if (jwt_decode(&ymtoken, encoded, public_key, strlen((char *)public_key)))
        perror("jwt_decode"), exit(-1);

    char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
    if (grants == NULL)
        perror("jwt_get_grants_json"), exit(-1);

    printf("redecoded: %s\n", grants);
}
