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

// OpenSSL headers
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define OPT_STRING "t:"
#define DEFAULT_SERVICE 'a'
#define DEFAULT_SERVER 'd'
#define DEFAULT_PORT "7777"
#define BACKLOG 5
#define COL_CERT "certs/cert.pem"
#define COL_KEY "private/key.pem"
#define ANA_CERT "temp/cert.pem"
#define RAND_KEY "temp/rand.key"
#define ENC_RAND_KEY "temp/rand.key.enc"
#define GEN_KEY "openssl rand -base64 32 > temp/rand.key"
#define ENCRYPT_KEY "openssl rsautl -encrypt -certin -inkey temp/cert.pem -in temp/rand.key -out temp/rand.key.enc"
#define USAGE "Usage: %s [-s server type -t service] address port message\n"
#define ECENTS "temp/coins.file"
#define ECENT_SIZE 256


//
// MACROS for protocol
//

// Message type

#define NEW_ANALYST      0
#define NEW_COLLECTOR    1
#define PAYMENT          2
#define SUCCESS_RECEIPT  3
#define ERROR_RECEIPT    4
#define NO_ANALYST_FOUND 5
#define COLLECTOR_FOUND  6
#define CLOSED_CON       7
#define ANALYST_FOUND    8
#define SUCCESS_CLOSE    9
#define CERT_ERROR      10

// Message type
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
extern  char            *recv_msg(CONN *conn, int *size, char *msg_type);
extern  int             send_msg(CONN *conn, char *buf, int size, char type);
extern  int             recv_public_cert(CONN *conn);
extern  int             error_handler(char msg_type);
extern  int             buy_ecent(CONN *conn, int amount);
extern  int             check_balance();
extern  int             send_ecent(CONN *conn, unsigned char *key, int key_length);

// Defined in encryptions.c
extern  unsigned char   *gen_rand_key(int *keylength);
extern  unsigned char   *encrypt_key(unsigned char *key, int keylength);
extern  X509            *createX509(char *filename);
extern  unsigned char   *encrypt_data(unsigned char *buf, int size, int *after_size, unsigned char *key, int keylength, unsigned char *iv);
extern  unsigned char *decrypt_data(unsigned char *buf, int size, int *after_size, unsigned char *key, int keylength, unsigned char *iv);
