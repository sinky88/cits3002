#include <arpa/inet.h>
#include <fcntl.h>
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
#include <ctype.h>


// OpenSSL headers
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define OPT_STRING "t:"
#define DEFAULT_BANK_ADDR "127.0.0.1"
#define DEFAULT_BANK_PORT "6552"
#define DEFAULT_SERVICE 'a'
#define BACKLOG 5
#define ANA_CERT "certs/cert.pem"
#define ANA_KEY "private/key.pem"

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
#define CERT_ERROR      10
#define COLLECTOR_CHECK 11



// More message types

#define REQUEST_FOR_COIN    'a'
#define SEND_COIN           'b'
#define DEPOSIT_COIN        'c'
#define APPROVAL_OF_COIN    'd'
#define DENIAL_OF_COIN      'e'
#define NO_FUNDS_ERROR      'f'

// Structures as part of protocol

typedef struct {
    uint32_t                size;
    char                    msg_type;
} MSG_HEADER;

//Structures for this software

typedef struct {
    BIO                     *bio;
    SSL                     *ssl;
    SSL_CTX                 *ctx;
    int                     sd;
} CONN;

// Defined in connections.c
extern  int             init_conn(CONN *conn);
extern  int             load_certs(CONN *conn);
extern  CONN            *establish_connection(char *addr, char *port);
extern  int             register_with_dir(CONN *conn, char service_type);
extern  char            *recv_msg(CONN *conn, int *size, char *type);
extern  int             send_msg(CONN *conn, char *buf, int size, char type);
extern  int             send_encrypt_msg(CONN *conn, char *buf, int size, char type, unsigned char *key, int key_length);
extern  unsigned char   *recv_encrypt_msg(CONN *conn, int *new_size, char *type, unsigned char *key, int key_length);
extern  int             send_public_cert(CONN *conn);
extern  int             error_handler(char msg_type);
extern  int             deposit_ecent(CONN *conn, char *buf, int size);


// Defined in encryptions
extern  unsigned char *encrypt_data(unsigned char *buf, int size, int *after_size, unsigned char *key, int keylength, unsigned char *iv);
extern  unsigned char   *decrypt_key(unsigned char *encrypted, int length, int *key_length);
extern  unsigned char   *decrypt_data(unsigned char *buf, int size, int *after_size, unsigned char *key, int keylength, unsigned char *iv);

// Defined in analysts.c
extern  char             *reverse_str(char *str);
extern  char             *find_mean(char *str, int *send_size);
extern  char             *find_maxsize(char *str);
extern  char             *rot13(char *s);


