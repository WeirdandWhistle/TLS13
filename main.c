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

    unsigned char server_private_key[SECRET_LENGTH];
    unsigned char server_public_key[SECRET_LENGTH];
    randombytes_buf(server_private_key, sizeof(server_private_key));

    int rc = crypto_scalarmult_base(server_public_key, server_private_key);
    assert(rc==0);

    unsigned char client_public_key[SECRET_LENGTH];
    get_X25519_key_share(ch.extensions, client_public_key);

    printf("Client pub key: "); print_hex(client_public_key, SECRET_LENGTH);
    
    
    unsigned char shared_secret[SECRET_LENGTH];
    if(crypto_scalarmult(shared_secret, server_private_key, client_public_key) != 0){
        assert(0 && "Shared secret calculation failed!");
    }

    ExtensionArray ea = {0};
    ea.length = 0;

    ea = add_key_share(ea, NAMED_GROUP_X25519, server_public_key, 32);
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

    free_handshake(send_hs);
    free(r_arr.ptr);

    unsigned char hash[32];
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    crypto_hash_sha256_update(&state, record.fragment, record.length);
    crypto_hash_sha256_update(&state, r.fragment, r.length);

    crypto_hash_sha256_final(&state, hash);

    unsigned char server_hs_traffic_secret[SECRET_LENGTH];
    process_server_handshake_traffic_secret(server_hs_traffic_secret, shared_secret, hash);

    printf("server traffic secret: "); print_hex(server_hs_traffic_secret, 32);

    EncryptedExtensions ee = {0};
    log_extensions(ee.extensions, 1);

    Array ee_arr = process_encrypted_extensions(ee);

    Handshake hs = {0};
    hs.body = ee_arr.ptr;
    hs.length = ee_arr.length;
    hs.msg_type = 8;

    free(hs_arr.ptr);
    hs_arr = process_handshake(hs);
    // free_handshake(hs);

    // free_record(r);
    r.fragment = hs_arr.ptr;
    r.length = hs_arr.length;
    r.type = 22;

    uint8_t nonce_counter = 0;

    unsigned char server_write_key[SECRET_LENGTH];
    generate_write_key(server_write_key, server_hs_traffic_secret);

    unsigned char server_write_iv[NONCE_LENGTH];
    generate_write_iv(server_write_iv, server_hs_traffic_secret);

    unsigned char nonce[NONCE_LENGTH];
    generate_nonce(nonce, server_write_iv, nonce_counter);

    printf("server_write_key: "); print_hex(server_write_key, sizeof(server_write_key));
    printf("server_write_iv: "); print_hex(server_write_iv, sizeof(server_write_iv));

    r_arr = encrypt_record(r, server_write_key, nonce);

    write(s, r_arr.ptr, r_arr.length);

    free(r_arr.ptr);

    sleep(1);

    free_encrypted_extensions(ee);

    // free(sh_arr.ptr);
    // free(hs_arr.ptr);
    // free(r_arr.ptr);
  
    free_client_hello(ch);
    free_handshake(handshake);
    free_record(record);

    return 0;
}