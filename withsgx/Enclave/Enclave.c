#include "stdint.h"
#include "Enclave_t.h"
#include <stdlib.h>
#include "string.h"
#include "sgx_trts.h"
#define BUFLEN 16

typedef struct {
    #define KEYLEN 256
    uint32_t state[KEYLEN];
} KEY;
KEY key;

void derive_key(KEY *key, uint8_t *pass, const size_t len)
{
    unsigned char buf[BUFLEN] = {0};
    size_t buflen = BUFLEN;
    uint32_t seed = 0;
    uint32_t rand_val;
    int i = 0;
    printdata((pass));
    if (len < BUFLEN)
        buflen = len;

    memcpy(&buf, pass, buflen);

    for (; i < BUFLEN - 4; i+=4){
        seed ^= (uint32_t) buf[i+0] <<  0
              | (uint32_t) buf[i+1] <<  8
              | (uint32_t) buf[i+2] << 16
              | (uint32_t) buf[i+3] << 24;
    }


    for (i = 0; i < KEYLEN; i++){
        rand_val=0;
        read_rand(&seed, &rand_val);
        key->state[i] =  rand_val & 0xffff;

    }

}

void encrypt(KEY *key, uint8_t *data, const size_t len)
{
    uint32_t i = 0, t = 0, x = 0, y = 0;
    uint32_t state[KEYLEN];

    memcpy(&state, key->state, sizeof(state));

    for (; i < len; i++)
    {
        x = (x + 1) % KEYLEN;
        y = (y + state[x]) % KEYLEN;

        t = state[x];
        state[x] = state[y];
        state[y] = t;

        t = (state[x] + state[y]) % KEYLEN;
        data[i] = state[t] ^ data[i];
    }
}


void encrypt_data(uint8_t* data, size_t len){
    encrypt(&key, data, BUFLEN);
}

int verify_pwd(uint8_t* master, uint8_t* master_pass, size_t len){
    derive_key(&key, master, len);
    encrypt(&key, master_pass, BUFLEN);

    if (strlen((char *) master) == strlen((char *) master_pass) &&
        memcmp(master, master_pass, strlen((char *) master)) == 0
       ) return 1;

    return 0;
}

void encrypt_masterpwd(uint8_t* master, int len){
    printdata(master);
    derive_key(&key, master, strlen((char *) master));
    encrypt(&key, master, BUFLEN);
}




