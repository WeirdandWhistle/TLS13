#include "main.h"

void free_TLS_SERVER_STATE(TLS_SERVER_STATE* s){
    free(s->handshake_secret);
    free(s->master_secret);
    free(s->server_handshake_traffic_secret);
    free(s->client_handshake_traffic_secret);
    free(s->server_application_traffic_secret);
    free(s->client_application_traffic_secret);
    free(s->server_write_key);
    free(s->client_write_key);
    free(s->server_write_iv);
    free(s->client_write_iv);
    
}
int init_TLS_SERVER_STATE(TLS_SERVER_STATE* s){
    s->handshake_secret = malloc(SECRET_LENGTH);
    s->master_secret = malloc(SECRET_LENGTH);
    s->shared_secret = malloc(SECRET_LENGTH);
    s->server_handshake_traffic_secret = malloc(SECRET_LENGTH);
    s->client_handshake_traffic_secret = malloc(SECRET_LENGTH);
    s->server_application_traffic_secret = malloc(SECRET_LENGTH);
    s->client_application_traffic_secret = malloc(SECRET_LENGTH);
    s->server_write_key = malloc(SECRET_LENGTH);
    s->client_write_key = malloc(SECRET_LENGTH);
    s->server_write_iv = malloc(NONCE_LENGTH);
    s->client_write_iv = malloc(NONCE_LENGTH);

    s->cipher_suite = TLS_CHACHA20_POLY1305_SHA256_NUM;
    crypto_hash_sha256_init(&s->hash_state);
    return 0;
}
int main_state_mech(TLS_SERVER_STATE* state, TLSPlaintext record, int logging){

    int indent_level = 0;
    if(logging){
        if(state->state == ENCRYPTED){
            printf("Recived encrypted record:\n");
        }
        if(state->state == UNENCRYPTED){
            printf("Recived unencrypted record:\n");
        }

        indent_level++;
        log_record_simple(record, indent_level);
        indent_level++;
    }

    if(record.legacy_record_version[0] != 0x03 ||
         record.legacy_record_version[1] != 0X03){
        if(logging){
            indent(indent_level); printf("--- NOTE: record version is not TLS 1.2 (0x0303) ---\n");
         }
        // return -1;
    }

    switch (record.type){
    case HANDSHAKE_TYPE:
        // this prefroms the entire handshake until verifying peer's finished message/cert but wont matter becuase this implmentation DOES NOT SUPPORT PEER certs
        Handshake handshake = parse_handshake(record.fragment, record.length);

        if(handshake.msg_type != CLIENT_HELLO_TYPE){
            if (logging)
                printf("\n--- unencrypted handshake message ---\n");
            return -2;
        }

        ClientHello client_hello = parse_client_hello(handshake.body, handshake.length);
        free_handshake(handshake);

        if (logging){
            log_client_hello(client_hello, indent_level);
        }
        indent_level = 0;

        crypto_hash_sha256_update(&state->hash_state, record.fragment, record.length);
        int rc = ClientHello_ServerHello_handshake(state, client_hello, logging, indent_level);
        if(rc != 0){
            if(logging)
                printf("\n--- ClientHello/ServerHello handshake failed! ---\n");
            return -3;
        }

        free_client_hello(client_hello);

        state->state = ENCRYPTED;

        unsigned char hash[HASH_LENGTH];
        get_hash(&state->hash_state, hash);

        process_handshake_secret(state->handshake_secret, state->shared_secret, NULL);
        process_server_handshake_traffic_secret(state->server_handshake_traffic_secret, state->shared_secret, hash);
        process_client_handshake_traffic_secret(state->client_handshake_traffic_secret, state->shared_secret, hash);

        generate_write_key(state->server_write_key, state->server_handshake_traffic_secret);
        generate_write_iv(state->server_write_iv, state->server_handshake_traffic_secret);
        generate_write_key(state->client_write_key, state->client_handshake_traffic_secret);
        generate_write_iv(state->client_write_iv, state->client_handshake_traffic_secret);

        state->server_nonce_counter = 0;
        state->client_nonce_counter = 0;

        indent_level = 0;

        rc = send_null_EncryptedExtensions(state, logging, indent_level);

        if(rc!=0){
            if(logging)
                printf("\n--- Encrypted Extneions failed to send! ---\n");
            return -4;
        }

        break;
    
    case ALERT_TYPE:
        // printf("\n--- unexpected alert ---\n");
        unsigned char* iter = record.fragment;
        Alert alert = {0};
        alert.level = iter[0];
        alert.description = iter[1];
        indent(indent_level); printf("Alert\n");
        indent(indent_level+1); printf("Level %s %d\n", alert.level == WARNING_ALERT ? "WARNING" : "FATAL", alert.level);
        indent(indent_level+1); printf("Description %s(%d)\n", get_alert_name(alert.description), alert.description);
        break;

    case CHANGE_CIPHER_SPEC_TYPE:
        printf("\n--- CHANGE CIPHER SPEC ---\n");
        break;

    case APPLIACTION_TYPE:
        if(state->state == UNENCRYPTED){
            if(logging)
                printf("\n----- UNEXPECTED APPLICATION DATA (KEYS HAVE NOT BEEN ESTABLISHED!) -----\n");

            Alert alert = {0};
            alert.description = UNEXPECTED_MESSAGE_ALERT;
            alert.level = FATAL_ALERT;

            unsigned char alert_out[FULL_ALERT_LENGTH];
            process_full_alert_simple(alert_out, alert);

            write(state->socket, alert_out, sizeof(alert_out));

            return -40;
        }


        
        break;

    default:
        if(logging)
            printf("----- UNEXPECTED RECORD TYPE ------");
        return -50;
        break;
    }
    return 0;
}

int ClientHello_ServerHello_handshake(TLS_SERVER_STATE* state, ClientHello client_hello, int logging, int indent_level){
    unsigned char server_private_key[SECRET_LENGTH];
    unsigned char server_public_key[SECRET_LENGTH];
    if(state->cipher_suite == TLS_CHACHA20_POLY1305_SHA256_NUM){
        randombytes_buf(server_private_key, sizeof(server_private_key));
        int rc = crypto_scalarmult_base(server_public_key, server_private_key);
        if(rc != 0){
            if(logging)
                printf("\n--- scalar mult failed / generating public key failed ---\n");
            return -3;
        }
        unsigned char client_public_key[SECRET_LENGTH];
        get_X25519_key_share(client_hello.extensions, client_public_key);
        
        if(crypto_scalarmult(state->shared_secret, server_private_key, client_public_key) != 0){
            if(logging)
                printf("\n--- calculating shared_secret failed ---\n");
            return -4;
        }
    }

    unsigned char cipher_suite[2] = TLS_CHACHA20_POLY1305_SHA256;
    if(state->cipher_suite != TLS_CHACHA20_POLY1305_SHA256_NUM){
        if(logging)
            printf("\n----- THIS IMPLEMNETAION DOES NOT SUPPORT ANYTHING BUT CHACHA20_POLY1305_SHA256 -----\n");
        return -5;
    }
    unsigned char random[32];
    randombytes_buf(random, sizeof(random));
    ExtensionArray extensions = {};
    extensions = add_supported_versions(extensions);
    extensions = add_key_share(extensions, NAMED_GROUP_X25519, server_public_key, sizeof(server_public_key));
    ServerHello server_hello = create_server_hello(random, client_hello.legacy_session_id_length, client_hello.legacy_session_id,
                        cipher_suite, extensions_length(extensions), extensions);
    
    Array server_hello_array = process_server_hello(server_hello);
    
    Handshake handshake = {0};
    handshake.body = server_hello_array.ptr;
    handshake.length = server_hello_array.length;
    handshake.msg_type = SERVER_HELLO_TYPE;
    Array handshake_array = process_handshake(handshake);
    TLSPlaintext r = {0};
    r.fragment = handshake_array.ptr;
    r.length = handshake_array.length;
    r.type = HANDSHAKE_TYPE;
    r.legacy_record_version = malloc(2); r.legacy_record_version[0] = 0x03; r.legacy_record_version[1] = 0x03;
    Array r_array = process_record(r);
    
    write(state->socket, r_array.ptr, r_array.length);
    crypto_hash_sha256_update(&state->hash_state, r.fragment, r.length);
    if(logging){
        printf("\nSending unencrypted record:\n");
        indent_level = 1;
        log_record_simple(r, indent_level);
        indent_level++;
        log_server_hello(server_hello, indent_level);
        printf("\n");
    }
    free(r_array.ptr);
    free_record(r);
    free_handshake(handshake);
    free_server_hello(server_hello);
    return 0;
}
int send_null_EncryptedExtensions(TLS_SERVER_STATE* state, int logging, int indent_level){
    if(state->state != ENCRYPTED)
        return -1;
    unsigned hard_coded_length[] = {0x00, 0x00};
    Handshake handshake = {0};
    handshake.body = hard_coded_length;
    handshake.length = 2;
    handshake.msg_type = ENCRYPTED_EXTENSIONS;

    Array hs_array = process_handshake(handshake);

    TLSPlaintext r = {0};
    r.fragment = hs_array.ptr;
    r.type = HANDSHAKE_TYPE;
    r.length = hs_array.length;

    unsigned char nonce[NONCE_LENGTH];
    generate_nonce(nonce, state->server_write_iv, state->server_nonce_counter);

    Array r_array = encrypt_record(r, state->server_write_key, nonce);

    write(state->socket, r_array.ptr, r_array.length);

    if(logging){
        int id = indent_level;
        printf("Sending encrypted record:\n");
        id++;
        indent(id); printf("Length %d\n", r_array.length-5);
        indent(id); printf("Type application_data(23)\n");
        indent(id); printf("Version 0x0303\n");
        id++;
        indent(id); printf("Inner Plain Text:\n");
        indent(id); printf("Type %s(%d)\n", get_record_name(r.type), r.type);
        indent(id); printf("Length %d\n", r.length);
        id++;
        indent(id); printf("Handshake Type EncryptedExtensions(%d)\n", ENCRYPTED_EXTENSIONS);
        indent(id); printf("Handshake Length 2\n");
        id++;
        indent(id); printf("EncryptedExtensions (len=0)\n");
        id++;
        indent(id); printf("No extensions\n\n");
    }

    free(r_array.ptr);
    free_record(r);
    return 0;
}