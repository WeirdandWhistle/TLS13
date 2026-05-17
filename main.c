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

    TLS_SERVER_STATE state = {0};
    state.socket = s;
    init_TLS_SERVER_STATE(&state);

    while(1){
        TLSPlaintext r = read_record(state.socket);
        int rc = main_state_mech(&state, r, LOGGING);
        if(rc!=0)
            break;
    }

    return 0;
}