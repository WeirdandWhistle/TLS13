#include <stdio.h>
#include <stdint.h>
#include "constants.h"

void print_hex(unsigned char* a, int aSize){
    for(int i = 0; i<aSize;i++){
        printf("%02X",a[i]);
    }
    printf("\n");
}
uint32_t get_uint24(unsigned char* data){
    uint32_t num = (data[0] << 8*(3-1)) | (data[1] << 8*(3-2)) | data[2];
    return num;
}
void indent(int amount){
    for(int i = 0; i<amount*INDENT_PRODUCT;i++){
        putchar(INDENT_CHAR);
    }
}