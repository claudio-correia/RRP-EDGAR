#pragma once

#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <string>
#include <cstring>
#include <sstream>
#include <iomanip> 
#include <algorithm> 
#include <iostream>


using namespace std;

#define SEED_SIZE_OPENSSL 32
#define KEY_SIZE_OPENSSL 32
#define SEALED_DATA_SIZE 12 + 32 + 1 //includes de cifred data and the IV, assuming the long has 8bytes. 12 -> IV; 65 -> uid(private key); 1->pq sim
#define SIG_SIZE_OPENSSL 64
#define SGX_AESGCM_IV_SIZE 12
#define long_size 8
#define uid_SIZE 32


struct Pseudonym {                              //total size 154 bytes
	long epoch;                                 //size 8
    int i;                                      //size 4
    unsigned char sealedData[45];               //size 45 includes de cifred data and the IV, assuming the long has 8bytes. 12 -> IV; 65 -> uid(private key); 1->pq sim  
	unsigned char publicKey[32];                //size 32
	unsigned char Sig[64];                      //size 65
};

struct MySig {
	unsigned char Sig[64];
};


struct Capability { //size 8 + 8 + 154 + 8
    long delta_index_level0;
    long slot_size;    
	Pseudonym pseudonym;
    MySig *slot_sigs;
};


struct CapabilityHolder {
    Capability capability;
	unsigned char private_k[32];
};

//unsigned char enclave_public_key[32] = { 0xC6, 0xA2, 0xEE, 0x52, 0xFD, 0x46, 0x16, 0x25, 0xC9, 0x17, 0x68, 0x62, 0xA6, 0x15, 0xAE, 0x8E, 0x4A, 0x20, 0x9E, 0xEC, 0x11, 0xC4, 0x0D, 0x28, 0xAE, 0x24, 0xFA, 0x60, 0xF2, 0x0A, 0xD2, 0x26 };

class CryptoUtil
{
    public:
    
    unsigned char enclave_public_key[32] = { 0x35, 0x76, 0x04, 0x6C, 0x55, 0x1C, 0xDB, 0x3A, 0x07, 0x0C, 0xCB, 0x99, 0xDD, 0x52, 0xF6, 0x9D, 0xFF, 0x0A, 0x58, 0xD5, 0xE1, 0x61, 0x34, 0x76, 0x52, 0x2D, 0x97, 0x49, 0x92, 0xDD, 0x19, 0x12};
    EVP_PKEY *CSPubKey;        

    int init();
    void generate_priv_key(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* privateKeyOut);
    void aes_gcm_encrypt(unsigned char* decMessageIn, size_t len, unsigned char* encMessageOut, unsigned char* sym_key);
    void get_digest(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* digest);
    void get_digest(unsigned long epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* digest);
    void generate_pub_key(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* publicKeyOut);
    void request_sign(long request, unsigned char* private_k,unsigned char* signature_out); 
    int request_veirfy(long request, unsigned char * request_sig, Pseudonym* pseudonym);    
    void slot_sign(long epoch, long delta_index, long level, unsigned char* private_k, unsigned char* signature_out);
    int slot_verify(long epoch, long delta_index, long level,  unsigned char *signature, unsigned char* publicKey);
    void pseudo_sign(Pseudonym* pseudonym, EVP_PKEY *key);
    int pseudo_veirfy(Pseudonym* pseudonym);    
    void getRandomID( unsigned char* uid_priv);
    string char_to_hex(const unsigned char *hash, int size);


}; 