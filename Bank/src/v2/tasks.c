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
