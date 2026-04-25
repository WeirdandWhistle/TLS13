#include "main.h"

void HKDF_Expand_Label(unsigned char* out, char* Secret, unsigned char* Label, int Label_length, unsigned char* Context, uint8_t Context_length, int length){
    const uint16_t Length = htons(SECRET_LENGTH);
    unsigned char BASE_LABEL[] = {'t','l','s','1','3',' '};
    int len = 2 + 1 + 6 + Label_length + 1 + Context_length;
    unsigned char* buf = malloc(len);
    assert(buf!=NULL);

    uint8_t label_length = 6 + Label_length; 
    unsigned char label[label_length];
    combine_array(label, BASE_LABEL, sizeof(BASE_LABEL), Label, Label_length);

    unsigned char* iter = buf;

    memcpy(iter, &Length, 2);
    iter += 2;

    *iter = label_length;
    iter++;

    memcpy(iter, label, label_length);
    iter += label_length;

    *iter = Context_length;
    iter++;

    memcpy(iter, Context, Context_length);

    crypto_kdf_hkdf_sha256_expand(out, length, buf, len, Secret);    
    free(buf);
}
void process_server_handshake_traffic_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* transcipt_hash){
    unsigned char derived_secret[SECRET_LENGTH];
    process_base_derived_secret(derived_secret);

    unsigned char handshake_secret[SECRET_LENGTH];
    process_handshake_secret(handshake_secret, shared_secret, derived_secret);

    HKDF_Expand_Label(out, handshake_secret, "s hs traffic", sizeof("s hs traffic")-1, transcipt_hash, SECRET_LENGTH, SECRET_LENGTH);
}
void process_base_derived_secret(unsigned char* out){
    const unsigned char ZERO[SECRET_LENGTH] = {0};
    for(int i = 0; i<sizeof(ZERO);i++){
        assert(ZERO[i]==0);
    } 

    unsigned char early_secret[SECRET_LENGTH];
    crypto_kdf_hkdf_sha256_extract(early_secret, ZERO, 32, ZERO, 32);

    unsigned char empty_hash[SECRET_LENGTH];
    crypto_hash_sha256(empty_hash, NULL, 0);


    HKDF_Expand_Label(out, early_secret, "derived", sizeof("derived")-1, empty_hash, SECRET_LENGTH, SECRET_LENGTH);
}
void process_handshake_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* derived_secret){
    crypto_kdf_hkdf_sha256_extract(out, derived_secret, SECRET_LENGTH, shared_secret, SECRET_LENGTH);
}
void generate_nonce(unsigned char *out, unsigned char *iv, uint8_t counter){
	for(int i = 0; i<=10;i++){
		out[i] = iv[i];
	}
	out[11] = iv[11] ^ counter;
}
void generate_write_key(unsigned char* out, unsigned char* secret){
    HKDF_Expand_Label(out, secret, "key", 3, NULL, 0, SECRET_LENGTH);
}
void generate_write_iv(unsigned char* out, unsigned char* secret){
    HKDF_Expand_Label(out, secret, "iv", 2, NULL, 0, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
}