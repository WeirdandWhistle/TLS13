#include "../main.h"

/*Dont forget to free the ptr!*/
Array process_encrypted_extensions(EncryptedExtensions ee){
    ee.extensions_length = extensions_length(ee.extensions);
    int len = 2 + ee.extensions_length;

    unsigned char* buf = malloc(len);
    assert(buf!=NULL);

    unsigned char* iter = buf;

    memcpy(iter, &ee.extensions_length, 2);
    iter += 2;

    Array ex_arr = process_extensions(ee.extensions);
    memcpy(iter, ex_arr.ptr, ex_arr.length);
    free(ex_arr.ptr);

    Array arr = {0};
    arr.ptr = buf;
    arr.length = len;
    return arr;
}

void free_encrypted_extensions(EncryptedExtensions ee){
    free_extensions(ee.extensions);
}