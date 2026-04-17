#include "../main.h"

ClientHello parse_client_hello(unsigned char* data, int data_length){
    ClientHello ch = {0};

    unsigned char* iter = data;

    memcpy(ch.legacy_version, iter, 2);
    iter += 2;
    print_hex(ch.legacy_version, 2);

    memcpy(ch.random, iter, 32);
    iter += 32;
    // printf("copied random\n");

    memcpy(&ch.legacy_session_id_length, iter, 1);
    iter += 1;
    // printf("legacy_session_id_length %d\n",ch.legacy_session_id_length);

    ch.legacy_session_id = malloc(ch.legacy_session_id_length);
    memcpy(ch.legacy_session_id, iter, ch.legacy_session_id_length);
    iter += ch.legacy_session_id_length;
    // printf("copied legacy_session_id\n");

    // printf("suite length 0x%02x%02x\n",iter[0],iter[1]);
    memcpy(&ch.cipher_suites_length, iter, 2);
    iter += 2;
    ch.cipher_suites_length = ntohs(ch.cipher_suites_length); 
    // printf("cipher_suite length: %d\n",ch.cipher_suites_length);

    ch.cipher_suites = malloc(ch.cipher_suites_length);
    memcpy(ch.cipher_suites,  iter, ch.cipher_suites_length);
    iter += ch.cipher_suites_length;
    // printf("copied cipher_suites\n");    

    ch.legacy_compression_methods_length = *iter;
    iter += 1;
    // printf("legacy_compression_methods_length %d\n",ch.legacy_compression_methods_length);

    ch.legacy_compression_methods = malloc(ch.legacy_compression_methods_length);
    memcpy(ch.legacy_compression_methods, iter, ch.legacy_compression_methods_length);
    iter += ch.legacy_compression_methods_length;
    // print_hex(ch.legacy_compression_methods, ch.legacy_compression_methods_length);

    memcpy(&ch.extensions_length, iter, 2);
    iter += 2;
    ch.extensions_length = ntohs(ch.extensions_length);

    printf("start extension parsing. extension length %d\n",ch.extensions_length);
    // extension parsing
    printf("dif: %td\n",iter-data);

    return ch;
}
void free_client_hello(ClientHello ch){
    free(ch.legacy_session_id);
    free(ch.cipher_suites);
    free(ch.legacy_compression_methods);
}
