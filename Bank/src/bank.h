
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


/* DEFAULT CONFIGURATION */

// Server Configuration
#define DEFAULT_PORT "6552"
#define BACKLOG 10

#define BANK_CERT "certs/cert.pem"
#define BANK_KEY "private/key.pem"

#define OPT_STRING "p:"
#define TEMP_DIR "temp/"

// Bank Configuration
#define COINS_AVAIL     10000


/* COMMUNICATION */

// Message type
#define REQUEST_FOR_COIN    'a'
#define SEND_COIN           'b'
#define DEPOSIT_COIN        'c'
#define APPROVAL_OF_COIN    'd'
#define DENIAL_OF_COIN      'e'
#define NO_FUNDS_ERROR      'f'


/* STRUCTURES */

typedef struct {
    uint32_t                cid;
    bool                    spent;
} COIN;

typedef struct {
    BIO                     *bio;
    SSL                     *ssl;
    SSL_CTX                 *ctx;
} SSL_CONN;


/* FUNCTIONS */

// Defined in connections.c
extern  int             init_comm_on_port(char *port);
extern  int             serve_client(int listening_socket, SSL_CONN *conn);
extern  SSL_CONN        *establish_ssl_conn();
extern  char            *recv_msg(void *ssl, int *size, char *type);
extern  int             send_msg(void *ssl, char *buf, int size, char type);

// Defined in tasks.c
extern  int             generate_coin();
extern  int             coin_value(int cid);

// Defined in encryptions.c
extern  unsigned char   *gen_rand_key(int *keylength);
extern  unsigned char   *encrypt_string(unsigned char *str, int length, int *after_length);
extern  char            *decrypt_string(unsigned char *encrypted, int length);

extern  X509            *createX509(char *filename);

/* VARIABLES */
extern COIN b_coins[COINS_AVAIL];
extern int  coin_count;

extern FILE* FILE_OUTPUT;

