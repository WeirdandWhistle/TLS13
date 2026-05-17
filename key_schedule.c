#include "main.h"
#include <endian.h>

void HKDF_Expand_Label(unsigned char* out, unsigned char* Secret, unsigned char* Label, int Label_length, unsigned char* Context, uint8_t Context_length, uint16_t length){
    const uint16_t Length = htons(length);
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

    crypto_kdf_hkdf_sha256_expand(out, length, (char*)buf, len, Secret);    
    free(buf);
}
void process_server_handshake_traffic_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* transcipt_hash){
    unsigned char derived_secret[SECRET_LENGTH];
    process_base_derived_secret(derived_secret);

    unsigned char handshake_secret[SECRET_LENGTH];
    process_handshake_secret(handshake_secret, shared_secret, derived_secret);

    // printf("working handshake_secret: "); print_hex(handshake_secret, sizeof(handshake_secret));

    HKDF_Expand_Label(out, handshake_secret, (unsigned char*)"s hs traffic", sizeof("s hs traffic")-1, transcipt_hash, HASH_LENGTH, SECRET_LENGTH);
}
void process_client_handshake_traffic_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* transcipt_hash){
    unsigned char derived_secret[SECRET_LENGTH];
    process_base_derived_secret(derived_secret);

    unsigned char handshake_secret[SECRET_LENGTH];
    process_handshake_secret(handshake_secret, shared_secret, derived_secret);

    HKDF_Expand_Label(out, handshake_secret, (unsigned char*)"c hs traffic", sizeof("c hs traffic")-1, transcipt_hash, HASH_LENGTH, SECRET_LENGTH);
}
void process_base_derived_secret(unsigned char* out){
    const unsigned char ZERO[HASH_LENGTH] = {0};
    for(int i = 0; i< (int)sizeof(ZERO);i++){
        assert(ZERO[i]==0);
    } 

    unsigned char early_secret[SECRET_LENGTH];
    crypto_kdf_hkdf_sha256_extract(early_secret, ZERO, 32, ZERO, 32);

    unsigned char empty_hash[SECRET_LENGTH];
    crypto_hash_sha256(empty_hash, NULL, 0);


    HKDF_Expand_Label(out, early_secret, (unsigned char*)"derived", sizeof("derived")-1, empty_hash, SECRET_LENGTH, SECRET_LENGTH);
}
void process_handshake_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* derived_secret){
    if(derived_secret != NULL){
        crypto_kdf_hkdf_sha256_extract(out, derived_secret, SECRET_LENGTH, shared_secret, SECRET_LENGTH);
    } else {
        unsigned char ds[SECRET_LENGTH];
        process_base_derived_secret(ds);
        crypto_kdf_hkdf_sha256_extract(out, ds, SECRET_LENGTH, shared_secret, SECRET_LENGTH);
    }
}
void generate_nonce(unsigned char *out, unsigned char *iv, uint64_t counter){
    memset(out, 0, NONCE_LENGTH);
    uint64_t temp = htobe64(counter);
    memcpy(out+(NONCE_LENGTH - sizeof(uint64_t)), &temp, sizeof(uint64_t));
	for(int i = 0; i < NONCE_LENGTH; i++){
		out[i] = out[i] ^ iv[i];
	}
}
void generate_write_key(unsigned char* out, unsigned char* secret){
    HKDF_Expand_Label(out, secret, (unsigned char*)"key", 3, (unsigned char*)"", 0, SECRET_LENGTH);
}
void generate_write_iv(unsigned char* out, unsigned char* secret){
    HKDF_Expand_Label(out, secret, (unsigned char*)"iv", 2, (unsigned char*)"", 0, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
}
/*Handly little funciton for getting the sha256 hash with out finalying the running hash!*/
void get_hash(crypto_hash_sha256_state *ptr, unsigned char *out){
	crypto_hash_sha256_state copy;
	memcpy(&copy,ptr,sizeof(crypto_hash_sha256_state));
	crypto_hash_sha256_final(&copy, out);
}
void generate_finished_key(unsigned char* out, unsigned char* base_key){
    HKDF_Expand_Label(out, base_key, (unsigned char*)"finished", sizeof("finished")-1, (unsigned char*)"", 0, HASH_LENGTH);
}
void process_verify_data(unsigned char* out, unsigned char* finished_key, unsigned char* transcipt_hash){
    crypto_auth_hmacsha256(out, transcipt_hash, HASH_LENGTH, finished_key);
}
void process_client_application_traffic_secret_0(unsigned char* out, unsigned char* secret, unsigned char* transcipt_hash){
    HKDF_Expand_Label(out, secret, (unsigned char*)"c ap traffic", sizeof("c ap traffic")-1, transcipt_hash, HASH_LENGTH, SECRET_LENGTH);
}
void process_server_application_traffic_secret_0(unsigned char* out, unsigned char* secret, unsigned char* transcipt_hash){
    HKDF_Expand_Label(out, secret, (unsigned char*)"s ap traffic", sizeof("s ap traffic")-1, transcipt_hash, HASH_LENGTH, SECRET_LENGTH);
}
void process_master_secret(unsigned char* out, unsigned char* handshake_secret){
    unsigned char ZERO[HASH_LENGTH] = {0};
    for(int i = 0; i< (int)sizeof(ZERO);i++){
        assert(ZERO[i]==0);
    }

    unsigned char empty_hash[HASH_LENGTH];
    crypto_hash_sha256(empty_hash, NULL, 0);

    unsigned char temp_secret[SECRET_LENGTH];
    HKDF_Expand_Label(temp_secret, handshake_secret, (unsigned char*)"derived", sizeof("derived")-1, empty_hash, sizeof(empty_hash), SECRET_LENGTH);

    crypto_kdf_hkdf_sha256_extract(out, temp_secret, sizeof(temp_secret), ZERO, sizeof(ZERO));
}