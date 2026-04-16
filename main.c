#include <sodium.h>
#include <stdio.h>
#include "socket_manager.h"
#include "util.h"
#include "constants.h"

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


}