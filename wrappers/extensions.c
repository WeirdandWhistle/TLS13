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
        write_uint16(iter, ea.array[i].extension_type);
        iter += 2;

        write_uint16(iter, ea.array[i].extension_data_length);
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
        length +=4;
        length += ea.array[i].extension_data_length;
    }
    return length;
}
ExtensionArray add_extension(ExtensionArray ea, uint16_t type, uint16_t length, unsigned char* data){
    ea = grow_extensions(ea, 1);

    int i = ea.length - 1;

    ea.array[i].extension_data = malloc(length);
    memcpy(ea.array[i].extension_data, data, length);
    
    ea.array[i].extension_data_length = length;
    ea.array[i].extension_type = type;

    return ea;
}
ExtensionArray grow_extensions(ExtensionArray ea, int amount){
    ea.length+=amount;
    if(ea.array == NULL){
        ea.array = malloc(sizeof(Extension)*ea.length);
    } else {
        ea.array = realloc(ea.array, sizeof(Extension)*ea.length);
    }
    assert(ea.array!=NULL);
    return ea;
}
ExtensionArray add_key_share(ExtensionArray ea, uint16_t group, unsigned char* key_exchange, uint16_t key_exchange_length){
    ea = grow_extensions(ea, 1);

    uint16_t type = KEY_SHARE_EXTENSION_TYPE;
    
    int length = 2 + 2 + key_exchange_length;
    unsigned char* buf = malloc(length);
    assert(buf!=NULL);
    unsigned char* iter = buf;

    write_uint16(iter, group);
    iter += 2;

    write_uint16(iter, key_exchange_length);
    iter += 2;

    memcpy(iter, key_exchange, key_exchange_length);

    ea.array[ea.length-1].extension_type = type;
    ea.array[ea.length-1].extension_data_length = length;
    ea.array[ea.length-1].extension_data = buf;

    return ea;    
}
ExtensionArray add_supported_versions(ExtensionArray ea){
    unsigned char VERSION[] = {0x03, 0x04}; // constant
    const uint16_t type = SUPPORTED_VERSIONS_EXTENSION_TYPE;

    return add_extension(ea, type, 2, VERSION);
}
Extension* get_extension(ExtensionArray ea, uint16_t type){
    for(int i = 0; ea.length; i++){
        if(ea.array[i].extension_type == type){
            return &ea.array[i];
        }
    }
    return NULL;
}
void get_X25519_key_share(ExtensionArray ea, unsigned char* out){
    assert(out!=NULL);
    Extension* ex_ptr = get_extension(ea, KEY_SHARE_EXTENSION_TYPE);
    assert(ex_ptr!=NULL);
    Extension ex = *ex_ptr;

    unsigned char* iter = ex.extension_data;

    uint16_t length;
    memcpy(&length, iter, 2);
    iter += 2;
    length = ntohs(length);

    const uint16_t GROUP = NAMED_GROUP_X25519;

    while(1){
        uint16_t group;
        memcpy(&group, iter, 2);
        iter += 2;
        group = ntohs(group);

        uint16_t ke_len;
        memcpy(&ke_len, iter, 2);
        iter += 2;
        ke_len = ntohs(ke_len);

        if(group != GROUP){
            if(iter - ex.extension_data - 2 >= length){
                assert(0 && "Extension does not have X25519!");
            }
            iter += ke_len;
        } else {
            assert(ke_len==32);
            memcpy(out, iter, 32);
            break;
        }

    }
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