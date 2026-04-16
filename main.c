#include <sodium.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include "socket_manager.h"
#include "util.h"
#include "constants.h"
#include "tls13_types.h"

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

    unsigned char* buf = malloc(1001);
    int buf_length = read(s, buf, 1000);
    buf[buf_length] = 0;
    printf("%s",buf);

}