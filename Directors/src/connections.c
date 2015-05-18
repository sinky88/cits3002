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
    
    free(res);

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
    int size = 0;
    char msg_type = 0;
    char *service_type = recv_msg(conn, -1, &size, &msg_type);
    // Check what kind of connection we have
    if(msg_type == NEW_ANALYST) {
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
        send_msg(conn, NULL, 0, SUCCESS_RECEIPT);
        free(service_type);
    }
    if(msg_type == NEW_COLLECTOR) {
        printf("Received new collector entry information\n");
        info->service_type = *service_type;
        info->type = COLLECTOR;
        // Send confirmation of success
        send_msg(conn, NULL, 0, SUCCESS_RECEIPT);
        free(service_type);
    }
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
        if(strcmp(outcome, FOUND) != 0) {
            printf("No analysts found for service\n");
            // SSL write to collector to inform of failure
            char receipt = NO_ANALYST_FOUND;
            if(send_msg(conn, &receipt, sizeof(char), SUCCESS_RECEIPT) < 0) {
                exit(EXIT_FAILURE);
            }
            exit(EXIT_FAILURE);
        }
        if(strcmp(outcome, FOUND) == 0) {
            // SSL write to collector to inform of success
            char receipt = ANALYST_FOUND;
            if(send_msg(conn, &receipt, sizeof(char), SUCCESS_RECEIPT) < 0) {
                exit(EXIT_FAILURE);
            }
        }
        char sock_str[ID_LEN];
        recv(conn_socket, &sock_str, ID_LEN, 0);
        close(conn_socket);
        int sd = connect_domain_socket(sock_str);
        while(true) {
            // Recv from analyst process
            int msg_size = 0;
            char msg_type = 0;
            char *buf = recv_com(sd, &msg_size, &msg_type);
            // Send from SSL connection to collector
            send_msg(conn, buf, msg_size, msg_type);
            free(buf);
            // Receive from SSL connection to collector
            buf = recv_msg(conn, sd, &msg_size, &msg_type);
            // Send to analyst proccess
            send_com(sd, buf, msg_size, msg_type);
            free(buf);
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
        char receipt = COLLECTOR_FOUND;
        if(send_msg(conn, &receipt, sizeof(char), SUCCESS_RECEIPT) < 0) {
            MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
            header->msg_type = CLOSED_CON;
            send(sd, header, sizeof(MSG_HEADER), 0);
            exit(1);
        }
        while(true) {
            // Recv from SSL connection to analyst
            int msg_size = 0;
            char msg_type = 0;
            char *buf = recv_msg(conn, sd, &msg_size, &msg_type);
            // Send to collector process
            send_com(sd, buf, msg_size, msg_type);
            free(buf);
            // Recv from collector process
            buf = recv_com(sd, &msg_size, &msg_type);
            // Send from SSL connection to analyst
            send_msg(conn, buf, msg_size, msg_type);
            free(buf);
        }
        // If we got here we lost SSL connection to analyst
        MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
        header->msg_type = CLOSED_CON;
        send(sd, header, sizeof(MSG_HEADER), 0);
    }
    return 0;
}

char *recv_com(int sd, int *size, char *type)
{
    MSG_HEADER *header  = malloc(sizeof(MSG_HEADER));
    // Recv from analyst process
    recv(sd, header, sizeof(MSG_HEADER), 0);
    char *buf = malloc(header->size);
    *type = header->msg_type;
    *size = header->size;
    if(header->size <= 0) {
        return buf;
    }
    recv(sd, buf, *size, 0);
    return buf;
}

int send_com(int sd, char *buf, int size, char type)
{
    MSG_HEADER *header  = malloc(sizeof(MSG_HEADER));
    header->msg_type = type;
    header->size = size;
    // Send to collector process
    send(sd, header, sizeof(MSG_HEADER), 0);
    if(header->size > 0) {
        send(sd, buf, header->size, 0);
    }
    return 0;
}


char *recv_msg(CONN *conn, int sd, int *size, char *type)
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
    *type = msg_type;
    // TODO add more error handling
    if(msg_type != SUCCESS_RECEIPT && msg_type != NEW_COLLECTOR && msg_type != NEW_ANALYST) {
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
        // Let the connected process know of the error
        if(sd != -1) {
            send_com(sd, NULL, 0, CLOSED_CON);
        }
        return NULL;
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

