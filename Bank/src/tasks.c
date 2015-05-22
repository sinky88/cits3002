#include "bank.h"

int generate_coin()
{
    if(coin_count == COINS_AVAIL) return -1;
    
    int newid = rand()%2147483647;
    for (int i = 0; i < coin_count; i++) {
        if(newid==b_coins[i].cid) {
            i = 0;
            newid = rand()%2147483647;
        }
    }
    
    b_coins[coin_count].cid = newid;
    b_coins[coin_count].spent = false;
    
    coin_count++;
    
    return newid;
}

int coin_value(int cid)
{
    for (int i = 0; i < COINS_AVAIL; i++) {
        if(cid==b_coins[i].cid) {
            if(b_coins[i].spent) {
                return -1;
            }
            
            else {
                b_coins[i].spent = true;
                return 1;
            }
        }
    }
    return -1;
}

int file_get_coin_count()
{
    FILE* file;
    char* buf = malloc(20 * sizeof(char) );
    
    int count = 0;
    if( (file = fopen(COINS_LIST, "r")) == NULL ) return -1;
    
    while (fgets (buf , 100 , file) != NULL) count++;
    
    fclose(file);
    return count;
}


int file_generate_coin()
{
    
    if(coin_count == COINS_AVAIL) return -1;
    
    int newid = rand()%2147483647;
    FILE* file;
    char* buf = malloc(20 * sizeof(char) );
    
    
    if( (file = fopen(COINS_LIST, "r")) == NULL ) return -1;

    while (fgets (buf , 100 , file) != NULL)
    {
        int c = atoi(buf);
        if (newid==c) {
            fclose(file);
            return file_generate_coin();
        }
    }
    
    char *str = malloc( (10 + 1) * sizeof(char));
    sprintf(str, "%i", newid );
    int len = strlen(str);
    str[len] = '\n';
    
    fwrite ( str, sizeof(char), len+1, file );
    fclose(file);
    
    
    return newid;
}


int file_coin_value(int cid)

{
    FILE* file;
    if( (file = fopen(COINS_LIST, "r")) == NULL ) return -2;
    
    char* buf = malloc(20 * sizeof(char) );
    while (fgets (buf , 100 , file) != NULL)
    {
        int c = atoi(buf);
        
        if (cid==c) {
            //coin found
            
        }
    }

    
    
    for (int i = 0; i < COINS_AVAIL; i++) {
        if(cid==b_coins[i].cid) {
            if(b_coins[i].spent) {
                return -1;
            }
            
            else {
                b_coins[i].spent = true;
                return 1;
            }
        }
    }
    return -1;
}


