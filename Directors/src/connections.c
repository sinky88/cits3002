#include "directors.h"

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
    if(!SSL_CTX_use_certificate_file(conn->ctx, DIR_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate\n");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, DIR_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key\n");
        return -1;
    }
    return 0;
}

// Handler for sig action
//
//
void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// Function to wait for an SSL connection from analyst or collector

CONN *wait_for_connection(char *port)
{
    // Blank connection structure
    CONN *conn = malloc(sizeof (CONN));
    // Initialise connection
    init_conn(conn);
    // Load certificates
    load_certs(conn);
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx);
    
    // Set up structures for TCP connection
    struct addrinfo hints, *res;
    struct sigaction sa;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    
    getaddrinfo(NULL, port, &hints, &res);
    
    // Make a socket for listening
    int listen_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    free(res);
    
    int yes=1;
    
    // Make sure port is available
    if (setsockopt(listen_socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    
    // Bind it to the port
    if(bind(listen_socket, res->ai_addr, res->ai_addrlen) == -1) {
        close(listen_socket);
        perror("bind");
        exit(EXIT_FAILURE);
    }
    
    // Listen to the port
    listen(listen_socket, BACKLOG);
    
    // Handle reaping child processes
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    
    printf("Listening for connection on port %s\n", port);
    
    // Create process that will handle registering new processes
    handle_ipc(conn);
    
    // Accept() loop
    handle_new_connection(conn, listen_socket);
    
    return conn;
}


// Function for handling inter-process communication

int handle_ipc(CONN *conn)
{
    // Set up domain socket
    char sock_str[ID_LEN] = TEMP_DIR;
    char temp[ID_LEN];
    sprintf(temp, "%d", getpid());
    strcat(sock_str, temp);
    conn->domain_socket = create_domain_socket(sock_str);
    strcpy(conn->sock_str, sock_str);
    // Fork into new process
    if(fork()) {
        // Set up list of info entries
        INFO **info = malloc(sizeof(info));
        int info_count = 0;
        // Set up loop to communicate between processes
        while(true) {
            int sd;
            socklen_t address_length;
            struct sockaddr_un address;
            if(listen(conn->domain_socket, BACKLOG) < 0) {
                fprintf(stderr, "listen failed\n");
                exit(EXIT_FAILURE);
            }
            // Wait for new connection
            if((sd = accept(conn->domain_socket, (struct sockaddr *) &address, &address_length)) < 0) {
                perror("accept");
            }
            MSG *msg = malloc(sizeof(MSG));
            if(recv(sd, msg, sizeof(MSG), 0) < 0) {
                perror("recv");
            }
            if(msg->msg == CON_CLOSED) {
                // TODO handle connection closed case
                continue;
            }
            if(msg->msg == REGISTER_NEW) {
                printf("Registering new client\n");
                INFO *info_entry = malloc(sizeof(INFO));
                // Receive the info
                if((recv(sd, info_entry, sizeof(INFO), 0)) < 0) {
                    perror("recv");
                }
                if(info_entry->type == ANALYST) {
                    printf("Adding entry %c\n", info_entry->service_type);
                    add_entry(info, info_entry, &info_count);
                }
                if(info_entry->type == COLLECTOR) {
                    char *entry_sock_str;
                    if((entry_sock_str = check_match(info, info_entry, &info_count)) != NULL) {
                        remove_entry(info, entry_sock_str, &info_count);
                        printf("Sending FOUND message\n");
                        send(sd, FOUND, sizeof(FOUND), 0);
                        send(sd, entry_sock_str, ID_LEN, 0);
                    } else {
                        send(sd, NOT_FOUND, sizeof(NOT_FOUND), 0);
                    }
                }
                close(sd);
            }
            free(msg);
        }
    }
    return 0;
}

// Function to handle new connection from analyst or collector

int handle_new_connection(CONN *conn, int listen_socket)
{
    while(true) {
        struct sockaddr_storage their_addr;
        socklen_t addr_size;
        
        // Accept connection
        conn->sd = accept(listen_socket, (struct sockaddr *)&their_addr, &addr_size);
        
        if(conn->sd == -1) {
            perror("Accepting tcp connection");
            return -1;
        }
        
        if(!fork()) { // Fork process and check for child
            
            // Close the listening socket in the child
            close(listen_socket);
            
            // Set BIO into SSL structure
            conn->bio = BIO_new_socket(conn->sd, BIO_NOCLOSE);
            SSL_set_bio(conn->ssl, conn->bio, conn->bio);
            
            // Perform handshake
            if(SSL_accept(conn->ssl) != 1) {
                perror("SSL handshake");
                exit(EXIT_FAILURE);
            }
            break;
        }
        // Close the connected socket in the parent;
        close(conn->sd);
    }
    return 0;
}

// Function to register new analyst or collector connected via ssl

int register_client(CONN *conn, INFO *info)
{
    // Receive handshake
    MSG_HEADER *header;
    header = malloc(sizeof(MSG_HEADER));
    if(SSL_read(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
        perror("SSL read");
        exit(EXIT_FAILURE);
    }
    // Check what kind of connection we have
    if(header->msg_type == NEW_ANALYST) {
        // Allocate enough space to receive message
        char *service_type = malloc(sizeof(char));
        // Read message
        if(SSL_read(conn->ssl, service_type, sizeof(char)) <= 0) {
            perror("SSL read");
            return -1;
        }
        printf("Received new analyst entry information\n");
        info->service_type = *service_type;
        info->type = ANALYST;
        // Set up domain socket for communication with collector process
        char sock_str[ID_LEN] = TEMP_DIR;
        char temp[ID_LEN];
        sprintf(temp, "%d", getpid());
        strcat(sock_str, temp);
        conn->domain_socket = create_domain_socket(sock_str);
        strcpy(info->sock_str, sock_str);
        // Send confirmation of success
        header->msg_type = SUCCESS_RECEIPT;
        if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
            fprintf(stderr, "Error sending receipt\n");
            return -1;
        }
        free(service_type);
    }
    if(header->msg_type == NEW_COLLECTOR) {
        // Allocate enough space to receive message
        char *service_type = malloc(sizeof(char));

        // Read message
        if(SSL_read(conn->ssl, service_type, sizeof(char)) <= 0) {
            perror("SSL read");
            return -1;
        }
        printf("Received new collector entry information\n");
        info->service_type = *service_type;
        info->type = COLLECTOR;
        // Send confirmation of success
        header->msg_type = SUCCESS_RECEIPT;
        if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
            fprintf(stderr, "Error sending receipt\n");
            return -1;
        }
        free(service_type);
    }
    // Free memory
    free(header);
    return 0;
}


// Function to service the connected client or analyst

int serve_client(CONN *conn, INFO *info)
{
    // Connect domain socket and register our client
    MSG *msg = malloc(sizeof(MSG));
    msg->msg = REGISTER_NEW;
    strcpy(msg->sock_str, info->sock_str);
    
    int conn_socket = connect_domain_socket(conn->sock_str);
    send(conn_socket, msg, sizeof(MSG), 0);
    send(conn_socket, info, sizeof(INFO), 0);
    
    // COLLECTOR HANDLING PROCESS
    if(info->type == COLLECTOR) {
        char outcome[2];
        recv(conn_socket, &outcome, 2, 0);
        MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
        header->size = 0;
        if(strcmp(outcome, FOUND) != 0) {
            printf("No analysts found for service\n");
            // SSL write to collector to inform of failure
            header->msg_type = NO_ANALYST_FOUND;
            if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
                perror("SSL write");
            }
            free(header);
            exit(1);
        }
        if(strcmp(outcome, FOUND) == 0) {
            // SSL write to collector to inform of success
            header->msg_type = ANALYST_FOUND;
            if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
                perror("SSL write");
            }
        }
        char sock_str[ID_LEN];
        recv(conn_socket, &sock_str, ID_LEN, 0);
        close(conn_socket);
        int sd = connect_domain_socket(sock_str);
        while(true) {
            // Recv from analyst process
            recv(sd, header, sizeof(MSG_HEADER), 0);
            // Check if we still have a connection
            if(header->msg_type == CLOSED_CON) {
                if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
                    perror("SSL write");
                }
                printf("Lost connection to analyst\n");
                SSL_shutdown(conn->ssl);
                exit(1);
            }
            char *buf = malloc(header->size);
            recv(sd, buf, header->size, 0);
            // Send from SSL connection to collector
            if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
                perror("SSL write");
                break;
            }
            if(SSL_write(conn->ssl, buf, header->size) <= 0) {
                perror("SSL write");
                break;
            }
            // Receive from SSL connection to collector
            if(SSL_read(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
                perror("SSL read");
                break;
            }
            buf = malloc(header->size);
            if(header->size > 0) {
                if(SSL_read(conn->ssl, buf, header->size) <= 0) {
                    perror("SSL read");
                    break;
                }
            }
            if(header->msg_type == CLOSED_CON) {
                printf("Collector closed connection\n");
                exit(1);
            }
            // Send to analyst proccess
            send(sd, header, sizeof(MSG_HEADER), 0);
            send(sd, buf, header->size, 0);
        }
    }
    // ANALYST HANDLING PROCESS
    if(info->type == ANALYST) {
        if(listen(conn->domain_socket, BACKLOG) < 0) {
            fprintf(stderr, "listen failed\n");
            exit(EXIT_FAILURE);
        }
        int sd;
        // Wait for new connection
        printf("Waiting for connection to collector\n");
        if((sd = accept(conn->domain_socket, NULL, NULL)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        close(conn->domain_socket);
        // Send message to analyst to say we have successfully connected
        MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
        header->msg_type = COLLECTOR_FOUND;
        if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
            perror("SSL write");
            // Tell the collector we lost connection
            header->msg_type = CLOSED_CON;
            send(sd, header, sizeof(MSG_HEADER), 0);
            exit(1);
        }
        while(true) {
            // Recv from SSL connection to analyst
            if(SSL_read(conn->ssl, header, sizeof(MSG_HEADER)) <= 0 ) {
                perror("SSL_read");
                break;
            }
            if(header->msg_type == CLOSED_CON) {
                printf("Analyst closed connection\n");
                break;
            }
            char *buf = malloc(header->size);
            if(SSL_read(conn->ssl, buf, header->size) <= 0) {
                perror("SSL_read");
                break;
            }
            // Send to collector process
            send(sd, header, sizeof(MSG_HEADER), 0);
            send(sd, buf, header->size, 0);
            // Recv from collector process
            recv(sd, header, sizeof(MSG_HEADER), 0);
            buf = malloc(header->size);
            recv(sd, buf, header->size, 0);
            // Send from SSL connection to analyst
            if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
                perror("SSL write");
                break;
            }
            if(header->size == 0) {
                printf("Collector closed connection\n");
                break;
            }
            if(SSL_write(conn->ssl, buf, header->size) <= 0) {
                perror("SSL write");
                break;
            }
        }
        // If we got here we lost SSL connection to analyst
        header->msg_type = CLOSED_CON;
        send(sd, header, sizeof(MSG_HEADER), 0);
    }
    return 0;
}


// Function to set up domain socket

int create_domain_socket(char *sock_str)
{
    struct sockaddr_un address;
    int listen_socket,len;
    
    listen_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if(listen_socket < 0) {
        perror("socket");
        return -1;
    }
    
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, sock_str);
    unlink(address.sun_path);
    len = SUN_LEN (&address);
    
    if(bind(listen_socket, (struct sockaddr *)&address, len) != 0) {
        perror("bind");
        return -1;
    }
    return listen_socket;
}

// Function to connect to existing domain socket

int connect_domain_socket(char *sock_str)
{
    struct sockaddr_un address;
    int con_socket,len;
    
    con_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if(con_socket < 0) {
        perror("socket");
        return -1;
    }
    
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, sock_str);
    len = SUN_LEN (&address);
    
    if(connect(con_socket, (struct sockaddr *)&address, len) != 0) {
        perror("connect");
        return -1;
    }
    return con_socket;
}

