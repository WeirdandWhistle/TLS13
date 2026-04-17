#include "../main.h"

ExtensionArray parse_extensions(unsigned char* data, int data_length){
    int count = 0;
    // int running_length = 0;
    unsigned char* iter = data;
    uint16_t current_length = 0;
    while(1){
        count++;
        iter += 2;
        memcpy(&current_length, iter, 2);
        current_length = ntohs(current_length);
        iter += 2 + current_length;
        if(iter - data >= data_length){
            break;
        }
    }
    printf("calculated extension count %d\n",count);
    Extension* extensions = malloc(count * sizeof(Extension));

    iter = data;

    for(int i = 0; i<count;i++){
        memcpy(&extensions[i].extension_type, iter, 2);
        extensions[i].extension_type = ntohs(extensions[i].extension_type);
        iter += 2;

        memcpy(&extensions[i].extension_data_length, iter, 2);
        extensions[i].extension_data_length = ntohs(extensions[i].extension_data_length);
        iter += 2;

        extensions[i].extension_data = malloc(extensions[i].extension_data_length);
        assert(extensions[i].extension_data!=NULL);
        memcpy(extensions[i].extension_data, iter, extensions[i].extension_data_length);
        iter += extensions[i].extension_data_length;
    }
    ExtensionArray ea = {0};
    ea.array = extensions;
    ea.length = count;
    return ea;
}
void free_extensions(ExtensionArray ea){
    for(int i = 0; i<ea.length;i++){
        free(ea.array[i].extension_data);
    }
    free(ea.array);
}