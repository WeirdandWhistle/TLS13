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