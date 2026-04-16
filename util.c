#include <stdio.h>

void print_hex(unsigned char *a, int aSize){
    for(int i = 0; i<aSize;i++){
        printf("%02x",a[i]);
    }
    printf("\n");
}