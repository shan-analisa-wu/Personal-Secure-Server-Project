#ifndef _HTTP_H
#define _HTTP_H

#include <jwt.h>
#include <stdbool.h>
#include "buffer.h"
#include "jwtmgr.h"

struct bufio;

#define MAX_HEADER_NUM	100

enum http_method {
    HTTP_GET,
    HTTP_POST,
    HTTP_UNKNOWN
};

enum http_version {
    HTTP_1_0,
    HTTP_1_1
};

enum http_response_status {
    HTTP_OK = 200,
    HTTP_BAD_REQUEST = 400,
    HTTP_PERMISSION_DENIED = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_METHOD_NOT_ALLOWED = 405,
    HTTP_REQUEST_TIMEOUT = 408,
    HTTP_REQUEST_TOO_LONG = 414,
    HTTP_INTERNAL_ERROR = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_SERVICE_UNAVAILABLE = 503
};

enum http_header_name {
    HTTP_HEADER_CONNECTION,
    HTTP_HEADER_COOKIE,
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_CONTENT_ENCODING
};

enum http_jwt_check_ret {
    HTTP_JWT_CHECK_RET_OK = 0,
    HTTP_JWT_CHECK_RET_USER_NG = -1,
    HTTP_JWT_CHECK_RET_COOKIE_NG = -2,
    HTTP_JWT_CHECK_RET_COOKIE_EXPIRED = -3,
    HTTP_JWT_CHECK_RET_COOKIE_NOT_EXIST = -4,
};

struct http_transaction {
    /* request related fields */
    enum http_method req_method;
    enum http_version req_version;
    size_t req_path;        // expressed as offset into the client's bufio.
    size_t req_body;        // ditto
    int req_content_len;    // content length of request body

    /* response related fields */
    enum http_response_status resp_status;
    buffer_t resp_headers;
    buffer_t resp_body;

    struct http_client *client;


    char *req_headernames[MAX_HEADER_NUM];   //The array store header names
    char *req_headervalues[MAX_HEADER_NUM];  //The array store the value in the header
    int req_headercnt;
    jwtmgr *jwt; //object handle the java wen token
    int IsKeepAlive;  //if HTTP 1.1 version, do we need to keep connection
};

struct http_client {
    struct bufio *bufio;
};

void http_setup_client(struct http_client *, struct bufio *bufio);
bool http_handle_transaction(struct http_transaction *ta, struct http_client *self);
void http_add_header(buffer_t * resp, char* key, char* fmt, ...);
void http_transaction_clean(struct http_transaction *ta);

#endif /* _HTTP_H */
