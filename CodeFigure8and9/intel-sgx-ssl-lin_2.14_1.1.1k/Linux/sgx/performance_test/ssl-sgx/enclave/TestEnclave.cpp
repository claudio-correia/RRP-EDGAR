/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include "../../base-source/Core.cpp"

 
#include "TestEnclave.h"
#include "tSgxSSL_api.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>



//#include "src/ED25519_orlp.c"


#include <sgx_tcrypto.h>


Core core;


#define ADD_ENTROPY_SIZE	32
int run_global_enclave = 32;

typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;





void boot_enclave(int BF_size, int BF_k, long epoch_fraction, double delta_fraction){

    core.init(BF_size, BF_k, epoch_fraction, delta_fraction);
}







void problem_generate_user_pseudonyms(  Pseudonym *pseudonym, int N_pseudonyms, unsigned char* outgoingPseudoBuffer){
    



    for (long i = 0; i < N_pseudonyms; i++) { 

        unsigned char magic_enclave_private_key[64] = { 0x00, 0xA9, 0x57, 0x27, 0x1E, 0x5A, 0x15, 0xBA, 0x66, 0x25, 0xC0, 0xAF, 0x0C, 0x7D, 0xCC, 0x4F, 0x02, 0xF2, 0xE7, 0xF5, 0x97, 0xD8, 0x0D, 0x63, 0x09, 0x2B, 0x71, 0x07, 0x06, 0x79, 0x57, 0x4C, 0xEB, 0xD2, 0xB7, 0x5F, 0xC5, 0x45, 0xC0, 0xD0, 0x23, 0xA9, 0xBD, 0x59, 0xE0, 0xAD, 0xD2, 0x5B, 0x7F, 0x02, 0xB6, 0xBD, 0x2B, 0xC8, 0xF5, 0x94, 0x57, 0xCF, 0xB7, 0x45, 0x97, 0x7E, 0x20, 0x35};
        unsigned char shared_secret_sym_key[32]; //only 16 bytes will actualy be use for key material
        ed25519_key_exchange(shared_secret_sym_key, pseudonym->publicKey, magic_enclave_private_key);
    }   

    //core.create_user_pseudonym(NULL, NULL, NULL, NULL, NULL);
    //thread_generate_pseudonym((Pseudonym*)pseudonym, N_pseudonyms, outgoingPseudoBuffer);

    return;

}


void generate_user_pseudonyms( unsigned char* pseudonym, size_t PseudoSize, int N_pseudonyms, unsigned char* outgoingPseudoBuffer, size_t OutBufferSize){



    //problem_generate_user_pseudonyms((Pseudonym*)pseudonym, N_pseudonyms, outgoingPseudoBuffer);
    core.thread_generate_pseudonym((Pseudonym*)pseudonym, N_pseudonyms, outgoingPseudoBuffer);

    return;

}



void generate_user_pseudonyms_orlp( unsigned char* pseudonym, size_t PseudoSize, int N_pseudonyms, unsigned char* outgoingPseudoBuffer, size_t OutBufferSize){

    core.thread_generate_pseudonym_orlp((Pseudonym*)pseudonym, N_pseudonyms, outgoingPseudoBuffer);

    return;

}
