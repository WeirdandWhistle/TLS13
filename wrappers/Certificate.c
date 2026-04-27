#include "../main.h"

Certificate create_certificate(char* file){
    Certificate c = {0};
    CertificateEntry ce = {0};
    CertificateChain cc = {0};
    uint32_t cert_data_length = 0;
	//read cert.der file for binary encoding
	FILE *filePtr;
	filePtr = fopen(file,"r");
	
	fseek(filePtr, 0, SEEK_END);
	cert_data_length = (uint32_t)ftell(filePtr);
	
	rewind(filePtr);

	unsigned char *cert_data = malloc(cert_data_length);
	fread(cert_data, 1, cert_data_length, filePtr);

    ExtensionArray ea = {0};
    ea.length = 0;

    ce.cert_data = cert_data;
    ce.cert_data_length = cert_data_length;
    ce.extensions = ea;
    cc.length = 1;
    cc.certs[0] = ce;

    c.certificate_list = cc;
    c.certificate_list_length = certificate_chain_length(cc);

    c.certificate_request_context_length = 0;

    return c;
}
void free_certificate(Certificate c){
    for(int i = 0; i<c.certificate_list.length; i++){
        free(c.certificate_list.certs[i].cert_data);
        free_extensions(c.certificate_list.certs[i].extensions);
    }
}
Array process_certificate(Certificate c);
int certificate_chain_length(CertificateChain cc){
    int len = 0;
    for(int i = 0; i<cc.length; i++){
        len += 3;
        len += cc.certs[i].cert_data_length;
    }
    return len;
}
Array process_certificate_entry(CertificateEntry ce){
    uint16_t ex_length = extensions_length(ce.extensions);
    int len = 3 + ce.cert_data_length + 2 + ex_length;

    unsigned char* buf = malloc(len);
    assert(buf!=NULL);

    unsigned char* iter = buf;

    unsigned char* uint24_buf = process_uint24(ce.cert_data_length);
    memcpy(iter, uint24_buf, 3);
    iter += 3;
    free(uint24_buf);

    memcpy(iter, ce.cert_data, ce.cert_data_length);
    iter += ce.cert_data_length;

    memcpy(iter, &ex_length, 2);
    iter += 2;

    if(ex_length != 0){
        Array ex_arr = process_extensions(ce.extensions);
        memcpy(iter, ex_arr.ptr, ex_arr.length);
        free(ex_arr.ptr);
    }
    
    Array arr = {0};
    arr.ptr = buf;
    arr.length = len;
    return arr;
}