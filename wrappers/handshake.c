#include "../main.h"

Handshake parse_handshake(unsigned char* data, int data_length){
    Handshake hs = {0};

    unsigned char* iter = data;

    
    hs.msg_type = *iter;
    iter += 1;
    // printf("get msg_type %02x\n", hs.msg_type);

    
    hs.length = get_uint24(iter);
    iter += 3;
    // printf("get length %d\n",hs.length);
    
    unsigned char* buf = malloc(hs.length);
    assert(buf!=NULL);
    memcpy(buf, iter, hs.length);
    hs.body = buf;
    // printf("get body\n");

    return hs;
}
void free_handshake(Handshake handshake){
    free(handshake.body);
}
Array process_handshake(Handshake handshake, Array body){
    int length = 1 + 3 + handshake.length;

    unsigned char* buf = malloc(length);
    unsigned char* iter = buf;

    *iter = handshake.msg_type;
    iter++;

    memcpy(iter, process_uint24(handshake.length), 3);
    iter += 3;

    memcpy(iter, body.ptr, body.length);

    Array arr = {0};
    arr.length = length;
    arr.ptr = buf;
    return arr;
}