#include <sodium.h>

int main(){
    if(sodium_init()<0){
        printf("Crypto libary 'libsodium' did not init correctly.\nPANIC!\n");
        return 2;
    }
    unsigned char out[32];
    unsigned char mes[] = "123abc";
    crypto_hash_sha256(out,mes,6);

    for(int i = 0;i<sizeof(out);i++){
        printf("%02x",out[i]);
    }
    printf("\n");
    
}