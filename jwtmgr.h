#include <stdbool.h>

#define MAX_JWT_ITEM_NUM 1000

typedef struct _jwt_item
{
    char subname[100];
    char token[256];
    char grants[256];
}jwt_item;

typedef struct _jwtmgr
{
    int id;
    char key[128];
    jwt_item jwtpool[MAX_JWT_ITEM_NUM];
}jwtmgr;

extern jwt_item* gen_new_jwt_token(jwtmgr *mgr, char* sub, time_t iat, time_t exp);
extern int save_jwt_token(jwtmgr *mgr, jwt_item* jwtitem);
extern jwt_item* get_jwt_token(jwtmgr *mgr, char *sub);
extern jwtmgr* jwtmgr_create_and_init(int id, char* key);
extern void jwtmgr_free(jwtmgr *mgr);
extern int decode_jwt_token(jwtmgr *mgr, char *token, jwt_item* jwtitem);
extern int get_item_grant(jwt_item* jwtitem, char *grant, char *grantval);
