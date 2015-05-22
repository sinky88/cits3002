#include "directors.h"

/*
 CITS3002 Project 2015
 Name(s):             Benjamin Sinclair, Tjia Hwei Chew, Zhiyang Zhang, Jordan King
 Student number(s):   20153423, 21021956, 20830178, 21118935
 Date:                22nd May 2015
 */


int main(int argc, char *argv[])
{
    int result  = 0;
    char *port = DEFAULT_PORT;
    
    // Only one option right now
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            case 'p':
                if(optarg != NULL) {
                    port = optarg;
                } else {
                    fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
        }
    }
    // Wait for connection from analyst or collector
    wait_for_connection(port);
    return result;
}


