#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
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
unsigned char* process_uint24(uint32_t num){
    unsigned char buf[3];
    num = htons(num);
    buf[0] = (num >> 16) & 0xFF;
    buf[1] = (num >> 8) & 0xFF;
    buf[2] = (num) & 0xFF;
    return buf;
}