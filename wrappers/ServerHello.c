#include "../main.h"
/*
Dont forget to free the array poitner
*/
Array process_server_hello(ServerHello sh){
    int length = 2 + 32 + 1 + sh.legacy_session_id_echo_length + 2 + 1 + 2 + sh.extensions_length;
    unsigned char* buf = malloc(length);

    unsigned char* iter = buf;

    memcpy(iter, sh.legacy_version, 2);
    iter += 2;

    memcpy(iter, sh.random, 32);
    iter += 32;

    *iter = sh.legacy_session_id_echo_length;
    iter++;

    memcpy(iter, sh.legacy_session_id_echo, sh.legacy_session_id_echo_length);
    iter += sh.legacy_session_id_echo_length;

    memcpy(iter, sh.cipher_suite, 2);
    iter += 2;

    *iter = sh.legacy_compression_method;
    iter++;

    Array ex = process_extensions(sh.extensions);

    memcpy(iter, ex.ptr, ex.length);

    Array arr = {0};
    arr.length = length;
    arr.ptr = buf;
    return arr;
}

ServerHello create_server_hello(
        unsigned char random[32],
        uint8_t legacy_session_id_echo_length,
        unsigned char* legacy_session_id_echo,
        unsigned char cipher_suite[2],
        uint16_t extensions_length,
        ExtensionArray ea){
    ServerHello sh = {0};

    sh.legacy_version[0] = 0x03;
    sh.legacy_version[1] = 0x03;

    sh.random = random;

    sh.legacy_session_id_echo_length = legacy_session_id_echo_length;
    sh.legacy_session_id_echo = legacy_session_id_echo;

    sh.cipher_suite = cipher_suite;

    sh.legacy_compression_method = 0;

    sh.extensions_length = extensions_length;
    sh.extensions = ea;
    return sh;
}

void free_server_hello(ServerHello sh){
    free_extensions(sh.extensions);
}