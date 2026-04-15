#include <sodium.h>

void printHex(unsigned char *a, int aSize){
    for(int i = 0; i<aSize;i++){
        printf("%02x",a[i]);
    }
    printf("\n");
}

int main(){
    if(sodium_init()<0){
        printf("Crypto libary 'libsodium' did not init correctly.\nPANIC!\n");
        return 2;
    }
    unsigned char out[32];
    unsigned char mes[] = "123abc";
    crypto_hash_sha256(out,mes,6);

    printHex(out, sizeof(out));    
}