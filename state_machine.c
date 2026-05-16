#include "main.h"

void free_TLS_SERVER_STATE(TLS_SERVER_STATE s){
    free(s.handshake_secret);
    free(s.master_secret);
    free(s.server_handshake_traffic_secret);
    free(s.client_handshake_traffic_secret);
    free(s.server_application_traffic_secret);
    free(s.client_application_traffic_secret);
    free(s.server_write_key);
    free(s.client_write_key);
    free(s.server_write_iv);
    free(s.client_write_iv);
    
}
int main_state_mech(TLS_SERVER_STATE state, TLSPlaintext record, int logging){

    int indent_level = 0;
    if(logging){
        if(state.state == ENCRYPTED){
            printf("Recived encrypted record:\n");
        }
        if(state.state == UNENCRYPTED){
            printf("Recived unencrypted record:\n");
        }

        indent_level++;
        log_record_simple(record, indent_level);
        indent_level++;
    }

    if(record.legacy_record_version[0] != 0x03 ||
         record.legacy_record_version[1] != 0X03){
        if(logging)
            printf("--- record version is not TLS 1.2 (0x0303) ---\n");
        return -1;
    }

    switch (record.type){
    case HANDSHAKE_TYPE:
        Handshake handshake = parse_handshake(record.fragment, record.length);

        if(handshake.msg_type != CLIENT_HELLO_TYPE){
            if (logging)
                printf("--- unencrypted handshake message ---\n");
            return -2;
        }

        ClientHello client_hello = parse_client_hello(handshake.body, handshake.length);
        free_handshake(handshake);

        if (logging){
            log_client_hello(client_hello, indent_level);
            printf("\n");
        }
        indent_level = 0;

        unsigned char server_private_key[SECRET_LENGTH];
        unsigned char server_public_key[SECRET_LENGTH];
        unsigned char shared_secret[SECRET_LENGTH];

        if(state.cipher_suite == TLS_CHACHA20_POLY1305_SHA256_NUM){
             randombytes_buf(server_private_key, sizeof(server_private_key));

            int rc = crypto_scalarmult_base(server_public_key, server_private_key);
            if(rc != 0){
                if(logging)
                    printf("\n--- scalar mult failed / generating public key failed ---\n");
                return -3;
            }

            unsigned char client_public_key[SECRET_LENGTH];
            get_X25519_key_share(client_hello.extensions, client_public_key);

            
            if(crypto_scalarmult(shared_secret, server_private_key, client_public_key) != 0){
                if(logging)
                    printf("--- calculating shared_secret failed ---\n");
                return -4;
            }
        }

        unsigned char cipher_suite[2] = TLS_CHACHA20_POLY1305_SHA256;
        if(state.cipher_suite != TLS_CHACHA20_POLY1305_SHA256_NUM){
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

        free_client_hello(client_hello);

        Array server_hello_array = process_server_hello(server_hello);
        
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
        
        write(state.socket, r_array.ptr, r_array.length);

        if(logging){
            printf("\n--- Sending unencrypted record: ---\n");
            indent_level = 1;
            log_record_simple(r, indent_level);
            indent_level++;
            log_server_hello(server_hello, indent_level);
        }

        free(r_array.ptr);
        free_record(r);
        free_handshake(handshake);
        free_server_hello(server_hello);

        state.state = ENCRYPTED;

        break;
    
    case ALERT_TYPE:
        printf("\n--- unexpected alert ---\n");
        unsigned char* iter = record.fragment;
        Alert alert = {0};
        alert.level = iter[0];
        alert.description = iter[1];
        indent(indent_level); printf("Alert\n");
        indent(indent_level+1); printf("Level %s %d\n", alert.level == WARNING_ALERT ? "WARNING" : "FATAL", alert.level);
        indent(indent_level+1); printf("Description %s(%d)", get_alert_name(alert.description), alert.description);
        break;

    case CHANGE_CIPHER_SPEC_TYPE:
        printf("\n--- CHANGE CIPHER SPEC ---\n");
        break;

    case APPLIACTION_TYPE:
        if(state.state == UNENCRYPTED){
            if(logging)
                printf("\n----- UNEXPECTED APPLICATION DATA (KEYS HAVE NOT BEEN ESTABLISHED!) -----\n");

            Alert alert = {0};
            alert.description = UNEXPECTED_MESSAGE_ALERT;
            alert.level = FATAL_ALERT;

            unsigned char alert_out[FULL_ALERT_LENGTH];
            process_full_alert_simple(alert_out, alert);

            write(state.socket, alert_out, sizeof(alert_out));

            return -40;
        }



        break;

    default:
        printf("----- UNEXPECTED RECORD TYPE ------");
        break;
    }
    return 0;
}