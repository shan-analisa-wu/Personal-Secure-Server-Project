/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "globals.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

char * server_root;     // root from which static files are served
char server_root_real[1024];

const int MAX_HEADER_LEN = 2048;
const int MAX_ERROR_LEN = 2048;

/**
 * Check if the URL is valid
 * @param uri The url to be checked
 * @return return 0 if the URL is valid
 */
static int check_uri_valid(char *uri)
{
    char buff[1024];
    char realuri[1024];
    realuri[0] = 0;
    strcat(realuri, server_root);
    strcat(realuri, uri);

    if (strcasecmp(uri, "/api/login") == 0)
    {
        return 0;
    }
    else if (strcasestr(uri, "..") != NULL)
    {
        return -1;
    }
    else if (realpath(realuri, buff) == NULL)
    {
        return -2;
    }
    if (STARTS_WITH(buff, server_root))
    {
        return 0;
    }
    return -3;
}

/**
 * Pharse the header and save the information in a header
 * @param ta The http_transaction structure to store information
 * @param field_name The header name
 * @param field_value The corresponding header value
 * @return return 0 if saved successfully
 */
static int http_parse_save_header_info(struct http_transaction *ta, char* field_name, char* field_value)
{
    int index = -1;
    if (!strcasecmp(field_name, "Accept")) {
        index = HTTP_HEADER_ACCEPT;
    }
    if (!strcasecmp(field_name, "Connection")) {
        index = HTTP_HEADER_CONNECTION;
    }
    if (!strcasecmp(field_name, "Content-Type")) {
        index = HTTP_HEADER_CONTENT_TYPE;
    }
    if (!strcasecmp(field_name, "Cookie")) {
        index = HTTP_HEADER_COOKIE;
    }

    if (index != -1)
    {
        ta->req_headernames[index] = calloc(1, strlen(field_name) + 1);
        strcpy(ta->req_headernames[index], field_name);
        ta->req_headervalues[index] = calloc(1, strlen(field_value) + 1);
        strcpy(ta->req_headervalues[index], field_value);
    }
    return 0;
}

/**
 * Find the corresponding header value using header name
 * @param header The header to be found
 * @param ta The http_transaction structure store the value
 * @return return the header value
 */
static char* http_find_header_value(int header, struct http_transaction *ta)
{
    return ta->req_headervalues[header];
}

/**
 * Generate the string for the cookie
 * @param path th path
 * @param cookiename the name of the cookie
 * @param cookievalue the value of the cookie
 * @param maxageforsecond the maximum valid time
 * @param cookiestr the string to store the information for cookie
 */
static void http_gen_cookie_string(char *path, char *cookiename, char *cookievalue, char* maxageforsecond, char *cookiestr)
{
    strcpy(cookiestr, cookiename);
    strcat(cookiestr, "=");
    strcat(cookiestr, cookievalue);
    strcat(cookiestr, "; Max-Age=");
    strcat(cookiestr, maxageforsecond);
    strcat(cookiestr, "; path=");
    strcat(cookiestr, path);
    return;
}


/**
 * Check if a client is valid
 * @param ta The http_transaction that store the information of client
 * @return return true if the client is valid, otherwise return false
 */
static bool check_user_valid(struct http_transaction *ta)
{
    char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);

    if (strstr(body, "{") == NULL || strstr(body, "}") == NULL)
    {

        return false;
    }

    if (strstr(body, "user0") == NULL)
    {
        return false;
    }

    if (strstr(body, "thepassword") == NULL)
    {
        return false;
    }

    return true;
}

/**
 * Check if a request is valid
 * @param ta The http_transaction structure that store the information
 * @param validuser The parameter store the user name if the request is valid
 * @return return HTTP_JWT_CHECK_RET_OK if the request is valid
 */
static int http_check_jwt_req_valid(struct http_transaction *ta, char *validuser)
{
    char exp[64];

    if (ta->req_method == HTTP_GET)
    {
        jwt_item item;
        memset(&item, 0, sizeof(item));
        char *cookiestr = http_find_header_value(HTTP_HEADER_COOKIE, ta);
        if (cookiestr == NULL)
        {
            return HTTP_JWT_CHECK_RET_COOKIE_NOT_EXIST;    //cookie invalid
        }
        char *cookievalue = strchr(cookiestr, '=');
        cookievalue++;

        if (decode_jwt_token(ta->jwt, cookievalue, &item) < 0)
        {
            return HTTP_JWT_CHECK_RET_COOKIE_NG;     //cookie invalid
        }

        get_item_grant(&item, "exp", exp);
        int t = atoi(exp);
        int now = time(NULL);
        if (now > t)
        {
            return HTTP_JWT_CHECK_RET_COOKIE_EXPIRED;   //token expired
        }
        strcpy(validuser, item.subname);
        return HTTP_JWT_CHECK_RET_OK;
    }

    validuser[0] = 0;
    if (check_user_valid(ta) == false)
    {
        return HTTP_JWT_CHECK_RET_USER_NG;    //user invalid
    }

    return HTTP_JWT_CHECK_RET_OK;
}

/**
 * Put the response header into http_transaction structure
 * @param ta The structure that store the information
 */
static void http_put_globl_response_header(struct http_transaction *ta)
{
    ta->IsKeepAlive = 0;
    char *reqconnattr = http_find_header_value(HTTP_HEADER_CONNECTION, ta);
    if (ta->req_version == HTTP_1_1)
    {
        if (reqconnattr != NULL)
        {
            if (!strcmp(ta->req_headervalues[HTTP_HEADER_CONNECTION], "close"))
            {
                http_add_header(&ta->resp_headers, "Connection", "close");
            }
            else
            {
                ta->IsKeepAlive = 1;
                http_add_header(&ta->resp_headers, "Connection", "keep-alive");
            }
        }
        else
        {
            ta->IsKeepAlive = 1;
            http_add_header(&ta->resp_headers, "Connection", "keep-alive");
        }
    }
    else
    {
        http_add_header(&ta->resp_headers, "Connection", "close");
    }
    return;
}

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2 || len > 8192)       // error, EOF, or less than 2 characters
    {
        return false;
    }

    //fprintf(stderr, "req_offset: %d, len: %d\n", req_offset, len);

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    //fprintf(stderr, "%s\n", request);
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
    {
        //fprintf(stderr, "http req method failed\n");
        return false;
    }

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
    {
        //fprintf(stderr, "http req path failed\n");
        return false;
    }

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);
    if (ta->req_path == -1)
    {
        return false;
    }
    char *http_version = strtok_r(NULL, CRLF, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
    {
        //fprintf(stderr, "http req version failed\n");
        return false;
    }

    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
    {
        //fprintf(stderr, "http req version invalid\n");
        return false;
    }

    return true;
}

/* Process HTTP headers. */
static bool http_process_headers(struct http_transaction *ta)
{
    for (;;)
    {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
        {
            return false;
        }
        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
        {
            return true;
        }
        header[len - 2] = '\0';
        /* Each header field consists of a name followed by a
         * colon (":") and the field value. Field names are
         * case-insensitive. The field value MAY be preceded by
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        char *field_value = strtok_r(NULL, " \t", &endptr);    // skip leading & trailing OWS
        if (field_value == NULL)
            return false;


        if (!strcasecmp(field_name, "Content-Length"))
        {
            ta->req_content_len = atoi(field_value);
        }
        else
        {
            /* Handle other headers here. */
            if (http_parse_save_header_info(ta, field_name, field_value) < 0)
            {
                fprintf(stderr, "Header save failed, %s\n", field_name);
                return false;
            }
        }
    }
}

/* add a formatted header to the response buffer. */
void http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response
 * to the response buffer.  Used in send_response_header */
static void start_response(struct http_transaction * ta, buffer_t *res, int http_version)
{
    buffer_appends(res, "HTTP/1.1 ");

    switch (ta->resp_status)
    {
        case HTTP_OK:
            buffer_appends(res, "200 OK");
            break;
        case HTTP_BAD_REQUEST:
            buffer_appends(res, "400 Bad Request");
            break;
        case HTTP_PERMISSION_DENIED:
            buffer_appends(res, "403 Permission Denied");
            break;
        case HTTP_NOT_FOUND:
            buffer_appends(res, "404 Not Found");
            break;
        case HTTP_METHOD_NOT_ALLOWED:
            buffer_appends(res, "405 Method Not Allowed");
            break;
        case HTTP_REQUEST_TIMEOUT:
            buffer_appends(res, "408 Request Timeout");
            break;
        case HTTP_REQUEST_TOO_LONG:
            buffer_appends(res, "414 Request Too Long");
            break;
        case HTTP_NOT_IMPLEMENTED:
            buffer_appends(res, "501 Not Implemented");
            break;
        case HTTP_SERVICE_UNAVAILABLE:
            buffer_appends(res, "503 Service Unavailable");
            break;
        case HTTP_INTERNAL_ERROR:
        default:
            buffer_appends(res, "500 Internal Server Error");
            break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response, ta->req_version);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

/* Send an error response. */
static bool send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;

    return send_response(ta);
}

/* Send Not Found response. */
static bool send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found",
                      bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    return "text/plain";
}

/**
 * Handle invalid URL
 * @param ta The http_transaction structure to store the information
 * @param retval The return valid indicates whether the URL is valid
 */
static void handle_uri_invalid(struct http_transaction *ta, int retval)
{
    if (retval == -1)
    {
        send_not_found(ta);
    }
    else
    {
        send_not_found(ta);
    }
}

/* Handle HTTP transaction for static files. */
static bool handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (access(fname, R_OK))
    {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
    {
        send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
        return rc;
    }
    int filefd = open(fname, O_RDONLY);
    if (filefd == -1)
    {
        send_not_found(ta);
        return rc;
    }

    ta->resp_status = HTTP_OK;
    add_content_length(&ta->resp_headers, st.st_size);
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    success = bufio_sendfile(ta->client->bufio, filefd, NULL, st.st_size) == st.st_size;
    out:
    close(filefd);
    return success;
}

/**
 * Handle a request starts with api/ need authentication
 * @param ta The http_transaction structure store the transaction information
 * @param req_path The request path
 * @return return true if handled successfully otherwise return false
 */
static bool handle_api(struct http_transaction *ta, char * req_path)
{
    char buff[256] = {0};
    jwt_item *it;
    bool rc = false;
    bool isuserok = check_user_valid(ta);


    if (ta->req_method == HTTP_GET)
    {
        if (isuserok == false)
        {
            ta->resp_status = HTTP_OK;
            buffer_appends(&ta->resp_body, "{}");
            send_response(ta);
            rc = true;
        }
        else
        {
            it = get_jwt_token(ta->jwt, "user0");
            if (it != NULL)
            {
                ta->resp_status = HTTP_OK;
                buffer_appends(&ta->resp_body, it->grants);
                send_response(ta);
                rc = true;
            }
            else
            {
                ta->resp_status = HTTP_OK;
                buffer_appends(&ta->resp_body, "{}\r\n");
                send_response(ta);
                rc = true;
            }
        }
    }
    else
    {
        if (isuserok == true)
        {
            time_t t = time(NULL);
            jwt_item *it = gen_new_jwt_token(ta->jwt, "user0", t, t + token_expiration_time);
            save_jwt_token(ta->jwt, it);
            http_gen_cookie_string("/", "auth_token", it->token, "3600", buff);
            http_add_header(&ta->resp_headers, "Set-Cookie", buff);
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            ta->resp_status = HTTP_OK;
            buffer_appends(&ta->resp_body, it->grants);
            send_response(ta);
            rc = true;
        }
        else
        {
            send_error(ta, HTTP_PERMISSION_DENIED, "login request invalid");
            rc = false;
        }
    }
    return rc;
}

/* Set up an http client, associating it with a bufio buffer. */
void http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool http_handle_transaction(struct http_transaction *ta, struct http_client *self)
{
    ta->client = self;


    if (!http_parse_request(ta))
        return false;


    if (!http_process_headers(ta))
        return false;


    if (ta->req_content_len > 0)
    {
        int rc = bufio_read(self->bufio, ta->req_content_len, &ta->req_body);
        if (rc != ta->req_content_len)
        {
            fprintf(stderr, "Http req body read failed\n");
            return false;
        }

    }


    buffer_init(&ta->resp_headers, 1024);
    http_add_header(&ta->resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta->resp_body, 0);


    http_put_globl_response_header(ta);

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    if (req_path == NULL)
    {
        return false;
    }

    bool rc = false;
    if (ta->req_method == HTTP_UNKNOWN)
    {
        send_error(ta, HTTP_NOT_IMPLEMENTED, "not implement http method");
        rc = false;
    }


    int urlcheckret = check_uri_valid(req_path);
    if (urlcheckret < 0)
    {
        handle_uri_invalid(ta, urlcheckret);
        rc = false;
    }
    else if (strcasecmp(req_path, "/api/login") == 0)
    {
        rc = handle_api(ta, req_path);
    }
    else if (STARTS_WITH(req_path, "/private"))
    {
        char user[256];
        int valid;
        valid = http_check_jwt_req_valid(ta, user);
        if (valid == HTTP_JWT_CHECK_RET_USER_NG)
        {
            send_not_found(ta);
            rc = false;
        }
        else if (valid == HTTP_JWT_CHECK_RET_COOKIE_NG)
        {
            send_error(ta, HTTP_PERMISSION_DENIED, "cookie is not exist");
            rc = false;
        }
        else if (valid == HTTP_JWT_CHECK_RET_COOKIE_NOT_EXIST)
        {
            send_error(ta, HTTP_PERMISSION_DENIED, "cookie is not exist");
            rc = false;
        }
        else if (valid == HTTP_JWT_CHECK_RET_COOKIE_EXPIRED)
        {
            send_error(ta, HTTP_PERMISSION_DENIED, "cookie is expired");
            rc = false;
        }
        else
        {
            rc = handle_static_asset(ta, server_root);
        }
    }
    else
    {
        rc = handle_static_asset(ta, server_root);
    }

    buffer_delete(&ta->resp_headers);
    buffer_delete(&ta->resp_body);

    return rc;
}

/**
 * Free the dynamically allocated memory in ta
 * @param ta The structure stores all the transaction information
 */
void http_transaction_clean(struct http_transaction *ta)
{

    for (int i = 0; i < MAX_HEADER_NUM; i++)
    {
        if (ta->req_headernames[i] != NULL)
        {
            free(ta->req_headernames[i]);
            ta->req_headernames[i] = NULL;
            free(ta->req_headervalues[i]);
            ta->req_headervalues[i] = NULL;
        }
    }
}