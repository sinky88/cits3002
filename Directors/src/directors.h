
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <sys/un.h>

// OpenSSL headers

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define OPT_STRING "p:"
#define DEFAULT_PORT "65434"
#define BACKLOG 5
#define DIR_CERT "certs/cert.pem"
#define DIR_KEY "private/key.pem"
#define TEMP_DIR "temp/"
#define TIMEOUT 1000
#define BUFSIZE 256

//
// MACROS for protocol
//

// Message type

#define NEW_ANALYST      0
#define NEW_COLLECTOR    1
#define DATA             2
#define SUCCESS_RECEIPT  3
#define ERROR_RECEIPT    4
#define NO_ANALYST_FOUND 5
#define COLLECTOR_FOUND  6
#define CLOSED_CON       7
#define ANALYST_FOUND    8
#define SUCCESS_CLOSE    9



//
// MACROS for program
//

// Types of info structure
#define ID_LEN          12

#define ANALYST         0
#define COLLECTOR       1


#define FOUND           "a"
#define NOT_FOUND       "b"

#define REGISTER_NEW    0
#define CON_CLOSED      1


// Structures as part of protocol

typedef struct {
    uint32_t                 size;
    char                     msg_type;
} MSG_HEADER;

// Structures for this software

typedef struct {
    SSL                     *ssl;
    SSL_CTX                 *ctx;
} CONN;

typedef struct {
    char                    type; // Analyst or collector
    char                    service_type; // Type of service offered/required
    int                     client_id;  // ID of Analyst or Collector
    SSL                     *a_ssl;     // Connection to the analyst
    SSL                     *c_ssl;     // Connection to the collector
} INFO;

typedef struct node {
    INFO *info;
    struct node * next;
} node_t;

// Defined in connections.c
extern  int             init_conn(CONN *conn);
extern  int             load_certs(CONN *conn);
extern  int             *wait_for_connection(char *port);
extern  int             register_client(CONN *conn, node_t *analyst_list, node_t *collector_list, int *client_id);
extern  int             service_collectors(node_t *collector_list);
extern  char            *recv_msg(void *ssl, int *size, char *type, bool *error);
extern  int             send_msg(void *ssl, char *buf, int size, char type);
extern  int             error_handler(char msg_type);


// Defined in lists.c
extern  node_t          *create_list(INFO *info);
extern  int             *add_entry(node_t *head, INFO *info);
extern  INFO            *check_match(node_t *head, char service_type);
extern  INFO            *get_next_entry(node_t **head);
extern  int             remove_entry(node_t *head, int client_id);


