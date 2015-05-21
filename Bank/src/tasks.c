#include "bank.h"

int generate_coin()
{
    int newid = rand()%65536;
    for (int i = 0; i < coin_count; i++) {
        if(newid==b_coins[i].cid) {
            i = 0;
            newid = rand()%65536;
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
            if(b_coins[i].spent) return -1;
            else return 1;
        }
    }
    return -1;
}
