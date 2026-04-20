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
/*Dont forget to free the ptr!*/
Array process_extensions(ExtensionArray ea){
    int length = 0;
    for(int i = 0; i<ea.length;i++){
        length+=4;
        length+= ea.array[i].extension_data_length;
    }

    unsigned char* buf = malloc(length);
    unsigned char* iter = buf;

    for(int i = 0; i<ea.length;i++){
        memcpy(iter, &ea.array[i].extension_type, 2);
        iter += 2;

        memcpy(iter, &ea.array[i].extension_data_length, 2);
        iter += 2;

        memcpy(iter, ea.array[i].extension_data, ea.array[i].extension_data_length);
        iter += ea.array[i].extension_data_length;
    }

    Array arr = {0};
    arr.length = length;
    arr.ptr = buf;
    return arr;
}
int extensions_length(ExtensionArray ea){
    int length = 0;
    for(int i = 0; i<ea.length;i++){
        length+=4;
        length+= ea.array[i].extension_data_length;
    }
    return length;
}
ExtensionArray grow_extensions(ExtensionArray ea, int amount){
    ea.length+=amount;
    ea.array = realloc(ea.array, sizeof(Extension)*ea.length);
    assert(ea.array!=NULL);
}
ExtensionArray add_key_share(ExtensionArray ea, uint16_t group, unsigned char* key_exchange, uint16_t key_exchange_length){
    ea = grow_extensions(ea, 1);

    uint16_t type = KEY_SHARE_EXTENSION_TYPE;
    
    int length = 2 + 2 + key_exchange_length;
    unsigned char* buf = malloc(length);
    assert(buf!=NULL);
    unsigned char* iter = buf;

    memcpy(iter, &group, 2);
    iter += 2;

    memcpy(iter, &key_exchange_length, 2);
    iter += 2;

    memcpy(iter, key_exchange, key_exchange_length);

    ea.array[ea.length-1].extension_type = type;
    ea.array[ea.length-1].extension_data_length = length;
    ea.array[ea.length-1].extension_data = buf;

    return ea;    
}
void log_extensions(ExtensionArray ea, int indent_level){
    int id = indent_level;
    indent(id); printf("extensions:\n");
    id++;
    for(int i = 0; i<ea.length;i++){
        indent(id); printf("extension_type=%s(%d), length=%d\n",get_extension_name(ea.array[i].extension_type), ea.array[i].extension_type, ea.array[i].extension_data_length);
        indent(id+1); print_hex(ea.array[i].extension_data, ea.array[i].extension_data_length);
    }
}
char* get_extension_name(uint16_t type){
    switch(type){
        case 0:
            return "server_name";
        case 1:
            return "max_fragment_length";
        case 5:
            return "status_request";
        case 10:
            return "supported_groups";
        case 13:
            return "signature_algorithms";
        case 14:
            return "use_srtp";
        case 15:
            return "heartbeat";
        case 16:
            return "application_layer_protocol_negotiation";
        case 18:
            return "signed_certificate_timestamp";
        case 19:
            return "client_certificate_type";
        case 20:
            return "server_certificate_type";
        case 21:
            return "padding";
        case 41:
            return "pre_shared_key";
        case 42:
            return "early_data";
        case 43:
            return "supported_versions";
        case 44:
            return "cookie";
        case 45:
            return "psk_key_exchange_modes";
        case 47:
            return "certificate_authorities";
        case 48:
            return "oid_filters";
        case 49:
            return "post_handshake_auth";
        case 50:
            return "signature_algorithms_cert";
        case 51:
            return "key_share";    
        default:
            return "unknown";
    }
}