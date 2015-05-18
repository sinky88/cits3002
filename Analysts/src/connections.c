#include "analysts.h"

int init_conn(CONN *conn)
{
    // Initialise OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    
    // Set up the SSL context
    conn->ctx = SSL_CTX_new(SSLv3_method());
    return 0;
}

int load_certs(CONN *conn)
{
    // Load own certificate
    if(!SSL_CTX_use_certificate_file(conn->ctx, ANA_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, ANA_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key");
        return -1;
    }
    return 0;
}


CONN *establish_connection(char *addr, char *port)
{
    // Blank connection structure
    CONN *conn = malloc(sizeof (CONN));
    // Initialise connection
    init_conn(conn);
    // Load certificates
    load_certs(conn);
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx);
    
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    getaddrinfo(addr, port, &hints, &res);
    
    conn->sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    // Connect to server
    if(connect(conn->sd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("connection");
    }
    
    // Set BIO into SSL structure
    conn->bio = BIO_new_socket(conn->sd, BIO_NOCLOSE);
    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    
    // Perform handshake
    if(SSL_connect(conn->ssl) != 1) {
        perror("handshake\n");
    }
    
    printf("Connection Established\n");
    return conn;
}

int register_with_dir(CONN *conn, char service_type)
{
    // Send handshake info
    send_msg(conn, &service_type, sizeof(char), NEW_ANALYST);
    int size = 0;
    // Receive confirmation
    recv_msg(conn, &size);
    
    return 0;
}

char *recv_msg(CONN *conn, int *size)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header  = malloc(sizeof(header_size));
    // Receive message header
    if(SSL_read(conn->ssl, header, header_size) <= 0) {
        perror("SSL read");
        free(header);
        exit(EXIT_FAILURE);
    }
    char msg_type = 0;
    uint32_t network_size = 0;
    // Unpack integer and char
    memcpy(&network_size, header, sizeof(uint32_t));
    memcpy(&msg_type, header + sizeof(uint32_t), sizeof(char));
    // Make sure integer is in system byte order
    *size = ntohl(network_size);

    // TODO add more error handling
    if(msg_type != SUCCESS_RECEIPT) {
        printf("%i\n", msg_type);
        fprintf(stderr, "Error receiving message\n");
        exit(EXIT_FAILURE);
        // bad stuff
    }
    if(*size == 0) {
        return NULL;
    }
    char *buf = malloc(*size);
    // Receive data
    if(SSL_read(conn->ssl, buf, *size) <= 0) {
        perror("SSL read");
        free(header);
        free(buf);
        exit(EXIT_FAILURE);
    }    
    return buf;
}

int send_msg(CONN *conn, char *buf, int size, char type)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    // Create header for message
    char *header = malloc(header_size);
    // Make sure integer is in network byte order
    uint32_t network_size = htonl(size);
    // Pack integer and char
    memcpy(header, &network_size, sizeof(uint32_t));
    memcpy(header + sizeof(uint32_t), &type, sizeof(char));
    // Send message header
    if(SSL_write(conn->ssl, header, header_size) <= 0) {
        perror("SSL write");
        free(header);
        return -1;
    }
    if(size == 0) {
        return 0;
    }
    // Send data
    if(SSL_write(conn->ssl, buf, size) <= 0) {
        perror("SSL write");
        return -1;
    }
    
    return 0;
}


int send_public_cert(CONN *conn)
{
    FILE *fp = fopen(ANA_CERT, "r");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    rewind(fp);
    char *buf = malloc(size);
    fread(buf, size, 1, fp);
    fclose(fp);
    send_msg(conn, buf, size, SUCCESS_RECEIPT);
    return 0;
}




