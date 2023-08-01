#pragma once
#include "ED25519_orlp.h"

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

struct HaaCertificate { 
    
    unsigned char Esi[20]; //sizeof(long) + SGX_AESGCM_IV_SIZE
    unsigned char publicKey[32];
    unsigned char signature[64];

};


class CryptoUtil
{
    public:
    
    //symetric key to seal data 
    unsigned char Sym_CS[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

    //key to encrypt data to send to admin
    unsigned char shared_key_admin[16] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9 };


    //chave privada igual para todos os CSs, a seed usada-> const unsigned char seed[32] = "KGtKgs+0W5/GODnJJS3JvV81SLDS24A";
    const unsigned char encalve_seed[32] = "KGtKgs+0W5/GODnJJS3JvV8MSLDS24A"; //chave privada igual para todos os CSs
    unsigned char enclave_private_key[32] = { 0x4B, 0x47, 0x74, 0x4B, 0x67, 0x73, 0x2B, 0x30, 0x57, 0x35, 0x2F, 0x47, 0x4F, 0x44, 0x6E, 0x4A, 0x4A, 0x53, 0x33, 0x4A, 0x76, 0x56, 0x38, 0x31, 0x53, 0x4C, 0x44, 0x53, 0x32, 0x34, 0x41, 0x00 };
    unsigned char enclave_public_key[32] = { 0x35, 0x76, 0x04, 0x6C, 0x55, 0x1C, 0xDB, 0x3A, 0x07, 0x0C, 0xCB, 0x99, 0xDD, 0x52, 0xF6, 0x9D, 0xFF, 0x0A, 0x58, 0xD5, 0xE1, 0x61, 0x34, 0x76, 0x52, 0x2D, 0x97, 0x49, 0x92, 0xDD, 0x19, 0x12};
    //this key is the same but in a diferent formart to perform ECC key exanche in DH
    unsigned char magic_enclave_private_key[64] = { 0x00, 0xA9, 0x57, 0x27, 0x1E, 0x5A, 0x15, 0xBA, 0x66, 0x25, 0xC0, 0xAF, 0x0C, 0x7D, 0xCC, 0x4F, 0x02, 0xF2, 0xE7, 0xF5, 0x97, 0xD8, 0x0D, 0x63, 0x09, 0x2B, 0x71, 0x07, 0x06, 0x79, 0x57, 0x4C, 0xEB, 0xD2, 0xB7, 0x5F, 0xC5, 0x45, 0xC0, 0xD0, 0x23, 0xA9, 0xBD, 0x59, 0xE0, 0xAD, 0xD2, 0x5B, 0x7F, 0x02, 0xB6, 0xBD, 0x2B, 0xC8, 0xF5, 0x94, 0x57, 0xCF, 0xB7, 0x45, 0x97, 0x7E, 0x20, 0x35};

    EVP_PKEY *CSKeys;

    //admin publick key seed-> const unsigned char seed[32] = "7KDAa621Kgs+0W5/GOD28aSD.j9dija";
    // to delete unsigned char admin_private_key[] = { 0x37, 0x4B, 0x44, 0x41, 0x61, 0x36, 0x32, 0x31, 0x4B, 0x67, 0x73, 0x2B, 0x30, 0x57, 0x35, 0x2F, 0x47, 0x4F, 0x44, 0x32, 0x38, 0x61, 0x53, 0x44, 0x2E, 0x6A, 0x39, 0x64, 0x69, 0x6A, 0x61, 0x00 };
    unsigned char admin_public_key[32] = { 0xEC, 0xF4, 0x75, 0x02, 0x18, 0x8B, 0x12, 0x5C, 0x41, 0xF1, 0x35, 0xEE, 0xCF, 0xBC, 0x91, 0xEF, 0x70, 0xC6, 0x7C, 0xDD, 0x01, 0x2F, 0xAD, 0x6F, 0xCC, 0xB7, 0x8B, 0x11, 0x2F, 0x15, 0x82, 0x99 };
        

    int init();
    void generate_priv_key(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* privateKeyOut);
    void aes_gcm_encrypt(unsigned char* decMessageIn, size_t len, unsigned char* encMessageOut);
    void aes_gcm_encrypt(unsigned char* decMessageIn, size_t len, unsigned char* encMessageOut, unsigned char* sym_key);
    void aes_gcm_decrypt(unsigned char* encMessageIn, size_t len, unsigned char* decMessageOut, int lenOut);
    void aes_gcm_decrypt(unsigned char* encMessageIn, size_t len, unsigned char* decMessageOut, int lenOut, unsigned char* sym_key);
    void get_digest(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* digest);
    void get_digest(unsigned long epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* digest);
    void generate_pub_key(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* publicKeyOut);
    void request_sign(long request, unsigned char* private_k,unsigned char* signature_out); 
    int request_veirfy(long request, unsigned char * request_sig, Pseudonym* pseudonym);    
    void slot_sign(long epoch, long delta_index, long level, unsigned char* private_k, unsigned char* signature_out);
    int slot_verify(long epoch, long delta_index, long level,  unsigned char *signature, unsigned char* publicKey);
    void pseudo_sign(Pseudonym* pseudonym);
    void pseudo_sign(Pseudonym* pseudonym, EVP_PKEY *key);
    void pseudo_sign_orlp(Pseudonym* pseudonym, const unsigned char *public_key, const unsigned char *private_key);    
    int pseudo_veirfy(Pseudonym* pseudonym);    
    void unseal_pseudonym(unsigned char* sealed, unsigned char* uid);
    //Elliptic-curve Diffie–Hellman
    void ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);
    void ed25519_create_keypair(unsigned char *private_key, const unsigned char *seed);
    void ed25519_create_keypair(unsigned char *publick_key, unsigned char *private_key, const unsigned char *seed);    
    void ed25519_create_keypair(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* privateKeyOut);
    void getRandomID( unsigned char* uid_priv);
    string char_to_hex(const unsigned char *hash, int size);


}; 