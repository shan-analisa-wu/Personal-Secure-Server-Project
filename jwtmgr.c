

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jwt.h>
#include "jwtmgr.h"

/**
 * Generate new jwt
 * @param mgr The jwt manager
 * @param sub The user name
 * @param iat The time generate the token
 * @param exp The expiration time
 * @return return the jwt_item generated
 */
jwt_item* gen_new_jwt_token(jwtmgr *mgr, char* sub, time_t iat, time_t exp)
{
    jwt_t *jwt;
    jwt_new(&jwt);
    jwt_add_grant(jwt, "sub", sub);
    jwt_add_grant_int(jwt, "iat", iat);
    jwt_add_grant_int(jwt, "exp", exp);
    jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)mgr->key, strlen(mgr->key));

    jwt_item* it = (jwt_item *)calloc(1, sizeof(jwt_item));
    strcpy(it->subname,sub);
    strcpy(it->token,jwt_encode_str(jwt));
    strcpy(it->grants, jwt_get_grants_json(jwt, NULL));
    jwt_free(jwt);
    return it;
}

/**
 * Save jwt information into jwtpool
 * @param mgr The jet manager
 * @param jwtitem The jet_item information to be stored
 * @return return 0 if saved successfully otherwise return -1
 */
int save_jwt_token(jwtmgr *mgr, jwt_item* jwtitem)
{
    for (int i = 0; i < MAX_JWT_ITEM_NUM; i++)
    {
        if (mgr->jwtpool[i].subname[0] == 0)
        {
            strcpy(mgr->jwtpool[i].subname, jwtitem->subname);
            strcpy(mgr->jwtpool[i].grants, jwtitem->grants);
            strcpy(mgr->jwtpool[i].token, jwtitem->token);
            return 0;
        }
    }
    return -1;
}

/**
 * Get the jwt token of a specific user name
 * @param mgr The jwt manager
 * @param sub The user name we need to search
 * @return return the corresponding jwt_item
 */
jwt_item* get_jwt_token(jwtmgr *mgr, char *sub)
{
    for (int i = 0; i < MAX_JWT_ITEM_NUM; i++)
    {
        if (strcmp(mgr->jwtpool[i].subname, sub) == 0)
        {
            return &mgr->jwtpool[i];
        }
    }

    return NULL;
}

/**
 * Decode the jwt
 * @param mgr The jwt manager
 * @param token The token to be decoded
 * @param jwtitem
 * @return return whether decode successfully
 */
int decode_jwt_token(jwtmgr *mgr, char *token, jwt_item* jwtitem)
{
    jwt_t *jwt;
    jwt_new(&jwt);

    int ret = jwt_decode(&jwt, token, (unsigned char *)mgr->key, strlen(mgr->key));
    if (ret == 0)
    {
        strcpy(jwtitem->grants, jwt_get_grants_json(jwt, NULL));
        strcpy(jwtitem->token, token);
        strcpy(jwtitem->subname, jwt_get_grant(jwt, "sub"));
    }
    jwt_free(jwt);
    return ret;
}


int get_item_grant(jwt_item* jwtitem, char *grant, char *grantval)
{
    char *p = strstr(jwtitem->grants, grant);
    if (p == NULL)
    {
        return 0;
    }

    while (1)
    {
        if (*p++ == ':')
        {
            break;
        }
    }

    char *q = grantval;
    while (1)
    {
        *q++ = *p++;
        if (*p == ',')
        {
            *q = 0;
            break;
        }
    }

    return 0;
}

/**
 * Create a jwt manager and jwt pool
 */
jwtmgr* jwtmgr_create_and_init(int id, char* key)
{
    jwtmgr *newmgr = (jwtmgr *)malloc(sizeof(jwtmgr));
    memset(newmgr, 0, sizeof(jwtmgr));
    newmgr->id = id;
    strcpy(newmgr->key, key);
    return newmgr;
}

/**
 * Free the memory in the jwt pool
 * @param mgr The jwt manager
 */
void jwtmgr_free(jwtmgr *mgr)
{
    if (mgr != NULL)
    {
        free(mgr);
    }
}