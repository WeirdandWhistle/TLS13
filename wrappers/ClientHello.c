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

    // unsigned char* buf = malloc(ch.extensions_length);
    // assert(buf!=NULL);

    // memcpy(buf, iter, ch.extensions_length);

    ch.extensions = parse_extensions(iter, ch.extensions_length);

    return ch;
}
void free_client_hello(ClientHello ch){
    free(ch.legacy_session_id);
    free(ch.cipher_suites);
    free(ch.legacy_compression_methods);
    free_extensions(ch.extensions);
}
void log_client_hello(ClientHello ch, int indent_level){
    int id = indent_level;
    indent(id); printf("ClientHello\n");
    id++;
    indent(id); printf("client_version=0x%02X%02X\n",ch.legacy_version[0],ch.legacy_version[1]);
    indent(id); printf("Random:\n");
    indent(id+1); print_hex(ch.random, 32);
    indent(id); printf("session_id (len=%d):\n",ch.legacy_session_id_length);
    indent(id+1); print_hex(ch.legacy_session_id, ch.legacy_session_id_length);
    indent(id); printf("cipher_suites (len=%d):\n",ch.cipher_suites_length);
    indent(id+1); print_hex(ch.cipher_suites, ch.cipher_suites_length);
    indent(id); printf("compression_methods (len=%d):\n",ch.legacy_compression_methods_length);
    indent(id+1); print_hex(ch.legacy_compression_methods, ch.legacy_compression_methods_length);
    log_extensions(ch.extensions,id);
}
