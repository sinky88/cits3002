#include "bank.h"



int send_msg(void *ssl, char *buf, int size, char type)
{
    
    // Create header for message
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header = malloc(header_size);
    
    // Make sure integer is in network byte order
    uint32_t network_size = htonl(size);
    memcpy(header, &network_size, sizeof(uint32_t));
    memcpy(header + sizeof(uint32_t), &type, sizeof(char));
    
    // Send message header
    if(SSL_write(ssl, header, header_size) <= 0) {
        perror("SSL write");
        free(header);
        return -1;
    }
    
    // If size is zero then no data to send
    if(size == 0) {
        return 0;
    }
    
    // Send data
    if(SSL_write(ssl, buf, size) <= 0) {
        perror("SSL write");
        free(header);
        return -1;
    }
    
    free(header);
    return 0;
}

char *recv_msg(void *ssl, int *size, char *type)
{
    
    // Receive message header
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header = malloc(header_size);
    
    if(SSL_read(ssl, header, header_size) <= 0) {
        perror("SSL read");
        free(header);
        return NULL;
    }
    char msg_type = 0;
    uint32_t network_size = 0;
    
    // Unpack integer and char
    memcpy(&network_size, header, sizeof(uint32_t));
    memcpy(&msg_type, header + sizeof(uint32_t), sizeof(char));
    
    // Make sure integer is in system byte order
    *size = ntohl(network_size);
    *type = msg_type;
    
    // If size is zero then no data to receive
    if(*size == 0) {
        return NULL;
    }
    
    // Receive data
    char *buf = malloc(*size);
    
    if(SSL_read(ssl, buf, *size) <= 0) {
        perror("SSL read");
        free(header);
        free(buf);
        return NULL;
    }
    
    return buf;
}

int load_certs(SSL_CONN *conn)
{
    // Load own certificate
    if(!SSL_CTX_use_certificate_file(conn->ctx, BANK_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate\n");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, BANK_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key\n");
        return -1;
    }
    return 1;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
 INIT_COMMUNICATION_ON_PORT(char *port) function returns an int referring to a socket that may be used for communications with clients. If the value it refers to is less than 0, we have an error
 */
int init_comm_on_port(char *port)
{
    int sockfd;  // listen on sock_fd
    struct addrinfo hints, *servinfo;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    
    //fill out serverinfo, rv checks for errors
    int rv;
    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        //return 1;
        exit(1);
    }
    
    // loop through all the results from serverinfo and bind to the first we can
    struct addrinfo *p;
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        
        int yes = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue; }
        break;
    }
    
    // if unable to bind send error message
    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        //return 2;
        exit(1);
    }
    
    // we're able to bind, no longer need servinfo
    freeaddrinfo(servinfo);
    
    //listen for connections and check for errors
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }
    
     printf("server: waiting for connections...\n");
    
    return sockfd;
}

SSL_CONN *establish_ssl_conn()
{
    
    // Blank connection structure
    SSL_CONN *conn = malloc(sizeof (SSL_CONN));
    
    // Initialise connection
    conn->ctx = SSL_CTX_new( SSLv3_method() );
    
    // Load certificates
    int err;
    if ( (err = load_certs(conn) ) == -1) {
        fprintf(stdout, "error loading certs\n");
        exit(EXIT_FAILURE);
    }
    
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx);
    // Load in socket descriptor
 
    return conn;
}

/*
 SERVE_CLIENT(CONN *conn) function
 */
int serve_client(int listening_socket, SSL_CONN *conn)
{
    socklen_t sin_size;
    struct sockaddr_storage their_addr;
    
    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        
        /* ACCEPT CLIENT AND SPECIFY THEIR DETAILS */
        int new_fd;
        if( (new_fd = accept(listening_socket, (struct sockaddr *)&their_addr, &sin_size) ) == -1) {
            perror("accept");
            continue;
        }
        
        //get address of client being served
        char s[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
        
        printf("bank: serve client on %s\n", s);
        
        conn->bio=BIO_new(BIO_s_socket());
        BIO_set_fd(conn->bio, new_fd, BIO_NOCLOSE);
        SSL_set_bio(conn->ssl, conn->bio, conn->bio);
        
        if(SSL_accept(conn->ssl) != 1) {
            perror("SSL handshake");
            exit(EXIT_FAILURE);
        }
        
        printf("SSL handshake complete\n");
        
        /* FIND OUT WHAT CLIENT NEEDS AND SERVE THEM */
        
        char i_type;
        int i_size;
        char *rcvd_message = recv_msg(conn->ssl,&i_size, &i_type);
        printf("received type: %c, size: %d\n", i_type, i_size);
        
        switch (i_type){
                
            case REQUEST_FOR_COIN:
            {
                int numcoins;
                if( (numcoins = atoi(rcvd_message)) == 0) {
                    printf("error\n");
                }
                
                //string to fixed size either 16 or 32
                
                
                for(int i = 0; i < numcoins; i++) {
                    int coinid = generate_coin();
                    

                    char *str = malloc(6);
                    sprintf(str, "%d", coinid );
                    
                    //char *str = malloc(32);
                    //int i = strlen(temp);
                    //memcpy(str, temp, i);
                    
                    //for(int j = i; j < 31; j ++) {
                    //    str[j] = '*';
                    //}
                    //str[31] = '\0';
                    
                    
                    int length = strlen(str) + 1;
                    int after_length;
                    unsigned char *encrypted_cid = encrypt_string((unsigned char *)str, length, &after_length);
                    printf("length = %d\n", after_length);
                    
                    
                    printf("outputcoin= %s, len=%d\n", str, (int)strlen(str));
                    
                    send_msg(conn->ssl, (char *)encrypted_cid, after_length, SEND_COIN);
                    
                    
                    
                    /*
                    char* str2 = decrypt_string(encrypted_cid, after_length);
                    if(str2==NULL) printf("error!\n");
                    
                    printf("decrypted value is %s\n", str2);
                    */
                    
                
                }
                break;
            }
                
            case DEPOSIT_COIN:
            {
                char* str2 = decrypt_string((unsigned char *)rcvd_message, i_size);
                
                if(str2==NULL) printf("error!\n");
                printf("decrypted value is %s\n", str2);
                
                
                int coinid = atoi(str2);
                if( coinid == 0) {
                    printf("error\n");
                }
                
                printf("coin id=%d\n", coinid);
                
                int val = coin_value(coinid);
                printf("val=%d\n", val);
                
                char output_type;
                
                if (val>0) output_type = APPROVAL_OF_COIN;
                else output_type = DENIAL_OF_COIN;
                
                send_msg(conn->ssl, NULL, 0, output_type);
                
                break;
            }
                
            case REQUEST_AUTH:
            {
                char *numstr = malloc(12);
                sprintf(numstr, "%d", auth_count ++);
                char *dirstr = malloc(strlen(numstr) + strlen(TEMP_DIR) + 1);
                // This is where we would check the trust list
                // outside of scope of project, asssume trust.
                
                strcat(dirstr, TEMP_DIR);
                strcat(dirstr, numstr);
                FILE *fp = fopen(dirstr, "w+");
                fwrite(rcvd_message, i_size, 1, fp);
                fclose(fp);
                free(dirstr);
                free(numstr);
                break;
            }
                
            case CHECK_AUTH:
            {
                char *cert1 = recv_msg(conn->ssl, &i_size, &i_type);
                printf("Received certificate for authentication\n");
                for(int i = 0; i < auth_count; i ++) {
                    char *numstr = malloc(12);
                    sprintf(numstr, "%d", i);
                    char *dirstr = malloc(strlen(numstr) + strlen(TEMP_DIR) + 1);
                    strcat(dirstr, TEMP_DIR);
                    strcat(dirstr, numstr);
                    printf("Looking for certificate %s\n", dirstr);
                    FILE *fp = fopen(dirstr, "r");
                    if(fp == NULL) {
                        fprintf(stderr, "Could not find certificate\n");
                        continue;
                    }
                    char *cert2 = malloc(i_size);
                    int bytes_read = fread(cert2, 1, i_size, fp);
                    fclose(fp);
                    if(bytes_read != i_size) {
                        free(cert2);
                        printf("Bytes read %i bytes recv %i\n", bytes_read, i_size);
                        printf("Cert does not match size\n");
                        continue;
                    }
                    int size = 0;
                    while(size < i_size) {
                        if((*cert1)++ != (*cert2)++) {
                            continue;
                        }
                        size ++;
                    }
                    free(cert2);
                    if(size != i_size) {
                        printf("Cert does not match\n");
                        send_msg(conn->ssl , NULL, 0, AUTH_FAILED);
                        continue;
                    }
                    printf("Found match\n");
                    send_msg(conn->ssl, NULL, 0, AUTH_SUCCESS);
                    break;
                }
                // If we got here auth failed
                send_msg(conn->ssl , NULL, 0, AUTH_FAILED);
                break;
            }
                
            default:
                printf("Invalid message type received: %c", i_type);
                return 0;
        }
        
        
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
        
        printf("BANK: served client connnecting from %s \n", s);
        
        //close connection
        close(new_fd);
        printf("hi!\n");
        
        /* CLIENT HAS BEEN SERVED */
        
    }
    
    return 0;
}
