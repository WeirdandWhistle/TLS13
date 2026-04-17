#include "main.h"

int main(){
    if(sodium_init() < 0){
        printf("Crypto libary 'libsodium' did not init correctly.\nPANIC!\n");
        return 2;
    }
    printf("setting up socket!\n");
    const int socket = start_socket(SOCKET_PORT, SOCKET_PORT);
    if(socket < 0){
        printf("Socket failed to start!\n");
        return 3;
    }

    printf("Now listening on port %d.\n",SOCKET_PORT);
    int s = accept_socket(socket);
    if(s < 0){
        printf("Socket faild to accept!\n");
        return 4;
    }

    TLSPlaintext record = read_record(s);

    printf("First record type is %02x the protcol version is %02x%02x and the length is %d\n",record.type,record.legacy_record_version[0],record.legacy_record_version[1],record.length);

    return 0;
}