#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
    unsigned char* buf = malloc(3);
    uint32_t a = htonl(num);
    buf[0] = (a >> 8) & 0xFF;
    buf[1] = (a >> 16) & 0xFF;
    buf[2] = (a >> 24) & 0xFF;
    return buf;
}
void write_uint16(unsigned char* p, uint16_t num){
    uint16_t a = htons(num);
    memcpy(p, &a, 2);
}
void combine_array(unsigned char* p, unsigned char* a, int a_len, unsigned char* b, int b_len){
    for(int i = 0; i<a_len+b_len;i++){
        p[i] = i<a_len ? a[i] : b[i-a_len]; 
    }
}