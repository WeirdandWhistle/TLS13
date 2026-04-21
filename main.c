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

    unsigned char LEGACY_VERSION[2] = {0x03, 0x03};

    TLSPlaintext record = read_record(s);

    printf("First record type is %02x the protcol version is %02x%02x and the length is %d\n",record.type,record.legacy_record_version[0],record.legacy_record_version[1],record.length);

    

    printf("start handshake parsing\n");
    Handshake handshake = parse_handshake(record.fragment, record.length);
    printf("start ClientHello parsing\n");
    ClientHello ch = parse_client_hello(handshake.body, handshake.length);

    log_client_hello(ch,1);

    unsigned char random_buf[32];
    randombytes_buf(random_buf, sizeof(random_buf));

    unsigned char cs[2] = TLS_CHACHA20_POLY1305_SHA256;

    ExtensionArray ea = {0};
    ea.length = 0;

    ea = add_key_share(ea, NAMED_GROUP_X25519, random_buf, 32);
    ea = add_supported_versions(ea);

    ServerHello sh = create_server_hello(random_buf, ch.legacy_session_id_length, ch.legacy_session_id,cs,extensions_length(ea),ea);

    Array sh_arr = process_server_hello(sh);

    Handshake send_hs = {0};
    send_hs.length = sh_arr.length;
    send_hs.body = sh_arr.ptr;
    send_hs.msg_type = SERVER_HELLO_HEADER;

    Array hs_arr = process_handshake(send_hs);

    TLSPlaintext r = {0};
    r.legacy_record_version = LEGACY_VERSION;
    r.type = HANDSHAKE_TYPE;
    r.length = hs_arr.length;
    r.fragment = hs_arr.ptr;

    Array r_arr = process_record(r);

    printf("record length %d, handshake length %d, serverhello_arr length %d\n",r.length,send_hs.length,sh_arr.length);
    printf("handshake output: "); print_hex(hs_arr.ptr, hs_arr.length);

    write(s, r_arr.ptr, r_arr.length);

    sleep(1);

    free(sh_arr.ptr);
    free(hs_arr.ptr);
    free(r_arr.ptr);

    free_client_hello(ch);
    free_handshake(handshake);
    free_record(record);

    return 0;
}