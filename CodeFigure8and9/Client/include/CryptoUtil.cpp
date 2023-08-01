#include "CryptoUtil.h"

int CryptoUtil::init()
{
	CSKeys = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, encalve_seed, 32);
	return 1;
}

void CryptoUtil::generate_priv_key(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* privateKeyOut)
{	
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &i, long_size);
	SHA256_Update(&sha256, &epoch, long_size);
	SHA256_Update(&sha256, uid, uid_SIZE);
	SHA256_Final(hash, &sha256);

	//cout << "\nsha: " << char_to_hex((unsigned char *)&hash, SHA256_DIGEST_LENGTH) << "\n";



 	EVP_PKEY *new_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, hash, 32);
 	//PEM_write_PrivateKey(stdout, new_key, NULL, NULL, 0, NULL, NULL);

	size_t key_size = KEY_SIZE_OPENSSL;
	EVP_PKEY_get_raw_private_key(new_key, privateKeyOut, &key_size);

    EVP_PKEY_free(new_key);


}

void CryptoUtil::aes_gcm_encrypt(unsigned char* decMessageIn, size_t len, unsigned char* encMessageOut)
{
	aes_gcm_encrypt(decMessageIn, len, encMessageOut, Sym_CS);

}

void CryptoUtil::aes_gcm_encrypt(unsigned char* decMessageIn, size_t len, unsigned char* encMessageOut, unsigned char* sym_key)
{

    EVP_CIPHER_CTX* ctx;
    int outlen;

	//printf("Plaintext:\n");
	//BIO_dump_fp(stdout, (const char*)decMessageIn, len);


    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, SGX_AESGCM_IV_SIZE, NULL);
    //generate IV
    RAND_bytes(encMessageOut, SGX_AESGCM_IV_SIZE); //
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, sym_key, encMessageOut );
    EVP_EncryptUpdate(ctx, encMessageOut + SGX_AESGCM_IV_SIZE, &outlen, (uint8_t*)decMessageIn, len);
 
	
	/* Output encrypted block */
    EVP_EncryptFinal_ex(ctx, encMessageOut + SGX_AESGCM_IV_SIZE, &outlen);
    /* Get MAC */
    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SGX_AESGCM_MAC_SIZE, encMessageOut); //we have a digital signatures, the MAC is not required


	//printf("\nFull Ciphertext:\n");
	//BIO_dump_fp(stdout, encMessageOut, lenOut); 

    EVP_CIPHER_CTX_free(ctx);

}

void CryptoUtil::aes_gcm_decrypt(unsigned char* encMessageIn, size_t len, unsigned char* decMessageOut, int lenOut){
	
	aes_gcm_decrypt(encMessageIn, len, decMessageOut, lenOut, Sym_CS);

}

void CryptoUtil::aes_gcm_decrypt(unsigned char* encMessageIn, size_t len, unsigned char* decMessageOut, int lenOut, unsigned char* sym_key)
	{

    


	EVP_CIPHER_CTX *ctx;
	int outlen, rv;
	//printf("AES GCM Derypt:\n");
	
	//printf("\nFull Ciphertext:\n");
	//BIO_dump_fp(stdout, encMessageIn, len); 

	ctx = EVP_CIPHER_CTX_new();
	/* Select cipher */
	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	/* Set IV length, omit for 96 bits */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SGX_AESGCM_IV_SIZE, NULL);
	/* Specify key and IV */
	EVP_DecryptInit_ex(ctx, NULL, NULL, sym_key, encMessageIn);


	/* Decrypt plaintext */
	EVP_DecryptUpdate(ctx, decMessageOut, &outlen, encMessageIn + SGX_AESGCM_IV_SIZE, lenOut);



	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	//EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE, encMessageIn);
	/* Finalise: note get no output for GCM */
	rv = EVP_DecryptFinal_ex(ctx, decMessageOut, &outlen);
	/* Print out return value. If this is not successful authentication
	 * failed and plaintext is not trustworthy.
	 */
	//printf("Plaintext:\n");
	//BIO_dump_fp(stdout, (const char*)decMessageOut, lenOut);



	//printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
	EVP_CIPHER_CTX_free(ctx);
}


void CryptoUtil::get_digest(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* digest)
{

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &i, long_size);
	SHA256_Update(&sha256, &epoch, long_size);
	SHA256_Update(&sha256, uid, uid_SIZE);
	SHA256_Final(digest, &sha256);
}

void CryptoUtil::get_digest(unsigned long epoch, unsigned char* sealedData, unsigned char* publicKey, unsigned char* digest)
{

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &epoch, long_size);
	SHA256_Update(&sha256, sealedData, SEALED_DATA_SIZE);
	SHA256_Update(&sha256, publicKey, KEY_SIZE_OPENSSL);
	SHA256_Final(digest, &sha256);
	
    /*cout << "epoch: "  << epoch << "\n"; 
    cout << "sealedData  : "  << char_to_hex(sealedData, 45) << "\n"; 
    cout << "publicKey  : "   << char_to_hex(publicKey, 32) << "\n";    
    cout << "digest : "  << char_to_hex(digest, 32) << "\n"; */
	
}

void CryptoUtil::generate_pub_key(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* publicKeyOut)
{	
	unsigned char hash[32];
	get_digest(uid, epoch, i, hash);

	//cout << "\nsha: " << char_to_hex((unsigned char *)&hash, SHA256_DIGEST_LENGTH) << "\n";


 	EVP_PKEY *new_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, hash, 32);
 	//PEM_write_PrivateKey(stdout, new_key, NULL, NULL, 0, NULL, NULL);

	size_t key_size = 32;
	EVP_PKEY_get_raw_public_key(new_key, publicKeyOut, &key_size);
    EVP_PKEY_free(new_key);


}

void CryptoUtil::request_sign(long request, unsigned char* private_k,unsigned char* signature_out)
{


	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &request, long_size);
	SHA256_Final(hash, &sha256);

    	
	//cout << "\n request_sign sha: " << char_to_hex((unsigned char *)&hash, SHA256_DIGEST_LENGTH) << "\n";

 	EVP_PKEY *new_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_k, KEY_SIZE_OPENSSL);


    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, new_key);
    
    size_t sig_size = SIG_SIZE_OPENSSL;
	EVP_DigestSign(md_ctx, signature_out, &sig_size, hash, SHA256_DIGEST_LENGTH);



    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(new_key);
	
}

int CryptoUtil::request_veirfy(long request, unsigned char * request_sig, Pseudonym* pseudonym)
{

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &request, long_size);
	SHA256_Final(hash, &sha256);

	//cout << "\n request_veirfy sha: " << char_to_hex((unsigned char *)&hash, SHA256_DIGEST_LENGTH) << "\n";

	//printHex(" request_veirfy hash2: " , hash, 32);
	//printHex("pbkey: " , pseudonym->publicKey, 32);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_PKEY *new_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pseudonym->publicKey, KEY_SIZE_OPENSSL);


    EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, new_key);

    size_t sig_size = SIG_SIZE_OPENSSL;
    int ret = EVP_DigestVerify(md_ctx, request_sig, sig_size, hash, SHA256_DIGEST_LENGTH);	


    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(new_key);

	if (ret == 1) {
		//cout << "signature ok\n" ; // signature ok
		return 1;
	} else if (ret == 0) {
		cout << "incorrect signature\n"; // incorrect signature 
	} else {
		cout <<  "error\n"; // error 
	}

	//cout << "--- sig ver r: "<< BN_bn2hex(bn_r) << "\n";
	//cout << "--- sig ver s: "<< BN_bn2hex(bn_s) << "\n";


	return -1;	

}

void CryptoUtil::slot_sign(long epoch, long delta_index, long level, unsigned char* private_k, unsigned char* signature_out)
{


        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, &epoch, long_size);
        SHA256_Update(&sha256, &delta_index,long_size);
        SHA256_Update(&sha256, &level, long_size);
        SHA256_Final(hash, &sha256);
        //printHex("slot_sign hash:" , hash, SHA256_DIGEST_LENGTH);

        

        EVP_PKEY *new_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_k, 32);


        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, new_key);
        
        size_t sig_size = 64;
        EVP_DigestSign(md_ctx, signature_out, &sig_size, hash, 32);



        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(new_key);


        
        //cout << "\nslot_sign MySig sigX: " <<  BN_bn2hex(r) << " sigY: " <<  BN_bn2hex(s);
        //cout << "\nepoch: " << epoch << " delta_index: " << delta_index << " level: " << level; //<< " private_k: " << private_k;

    
}


int CryptoUtil::slot_verify(long epoch, long delta_index, long level,  unsigned char *signature, unsigned char* publicKey)
{

        unsigned char hash[32];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, &epoch, long_size);
        SHA256_Update(&sha256, &delta_index,long_size);
        SHA256_Update(&sha256, &level, long_size);
        SHA256_Final(hash, &sha256);


        //printHex("slot_verify hash:" , hash, SHA256_DIGEST_LENGTH);


        EVP_PKEY *new_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, publicKey, 32);

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, new_key);

        size_t sig_size = 64;
        int ret = EVP_DigestVerify(md_ctx, signature, sig_size, hash, 32);   

        //cout << "\n slot_verify sign( index= " << delta_index << ", level= " <<  level << ")  e: " << epoch;
        //cout << "\n sig: " << char_to_hex(signature->Sig, 64) << "\n publicKey: " << char_to_hex(publicKey, 32);


        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(new_key);

        if (ret == 1) {
            //cout <<  "\nsignature ok slot_verify"; // signature ok
            return 1;
        } else if (ret == 0) {
            cout << "\nincorrect signature slot_verify"; // incorrect signature 

        } else {
            cout << "\nerror slot_verify"; // error 
        }





        return ret; 

}

void CryptoUtil::pseudo_sign(Pseudonym* pseudonym)
{
	pseudo_sign(pseudonym, CSKeys);	
}


void CryptoUtil::pseudo_sign(Pseudonym* pseudonym, EVP_PKEY *key)
{


	unsigned char hash[32];
	//print("pseudo_sign hash:");
	get_digest(pseudonym->epoch, pseudonym->sealedData, pseudonym->publicKey, hash);


    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new(); //se calhar nao preciso de estar sempre a inciar isto

    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, key);

	size_t sig_size = SIG_SIZE_OPENSSL;
	EVP_DigestSign(md_ctx, pseudonym->Sig, &sig_size, hash, 32);

	EVP_MD_CTX_free(md_ctx);
    //cout << "Sig : "  << char_to_hex(pseudonym->Sig, 64) << "\n"; 
	
}

void CryptoUtil::pseudo_sign_orlp(Pseudonym* pseudonym, const unsigned char *public_key, const unsigned char *private_key)
{


	unsigned char hash[32];
	//print("pseudo_sign hash:");
	get_digest(pseudonym->epoch, pseudonym->sealedData, pseudonym->publicKey, hash);


    ED25519_orlp::ed25519_sign(pseudonym->Sig, hash, 32, public_key, private_key);
	
}

int CryptoUtil::pseudo_veirfy(Pseudonym* pseudonym)
{

	unsigned char hash[SHA256_DIGEST_LENGTH];
	//print("pseudo_veirfy hash:");
	get_digest(pseudonym->epoch, pseudonym->sealedData, pseudonym->publicKey, hash);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, CSKeys);
    //cout << "Sig : "  << char_to_hex(pseudonym->Sig, 64) << "\n"; 

	size_t sig_size = SIG_SIZE_OPENSSL;
	size_t msg_size = SHA256_DIGEST_LENGTH;
    int ret = EVP_DigestVerify(md_ctx, pseudonym->Sig, sig_size, hash, msg_size);	

	EVP_MD_CTX_free(md_ctx);


	if (ret == 1) {
		//cout << "\nsignature ok, pseudo_veirfy"; // signature ok
		return 1;
	} else if (ret == 0) {
		cout << "\n ******** incorrect signature, pseudo_veirfy"; // incorrect signature 
	} else {
		cout << "\n  ********* error, pseudo_veirfy"; // error 
	} 
        
		
		

	return -1;	

}

//recover uid from the sealed data
void CryptoUtil::unseal_pseudonym(unsigned char* sealed, unsigned char* uid){
    

    int sealedLen = uid_SIZE + SGX_AESGCM_IV_SIZE;

    aes_gcm_decrypt(sealed, sealedLen, uid, uid_SIZE);



    //unsigned long uid = 0;
    //memcpy(&uid, text_nonce, uid_size);

    return;
}

//Elliptic-curve Diffie–Hellman
void CryptoUtil::ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key) {

    ED25519_orlp::ed25519_key_exchange(shared_secret, public_key, private_key);

}

//Elliptic-curve Diffie–Hellman create private key in special format
void CryptoUtil::ed25519_create_keypair(unsigned char *private_key, const unsigned char *seed){
    
	unsigned char ignore[32];
	ED25519_orlp::ed25519_create_keypair(ignore, private_key, seed);

}

//Elliptic-curve Diffie–Hellman create private key in special format
void CryptoUtil::ed25519_create_keypair(unsigned char *publick_key, unsigned char *private_key, const unsigned char *seed){
    

	ED25519_orlp::ed25519_create_keypair(publick_key, private_key, seed);

}

//Elliptic-curve Diffie–Hellman create private key in special format
void CryptoUtil::ed25519_create_keypair(unsigned char* uid, unsigned long epoch, unsigned long i, unsigned char* privateKeyOut)
{	
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &i, long_size);
	SHA256_Update(&sha256, &epoch, long_size);
	SHA256_Update(&sha256, uid, uid_SIZE);
	SHA256_Final(hash, &sha256);

	ed25519_create_keypair(privateKeyOut, hash);



}

void CryptoUtil::getRandomID( unsigned char* uid_priv){



 	EVP_PKEY *pkey = NULL;
 	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
 	EVP_PKEY_keygen_init(pctx);
 	EVP_PKEY_keygen(pctx, &pkey);


	size_t size = 32;
 	EVP_PKEY_get_raw_private_key(pkey, uid_priv, &size);

	EVP_PKEY_CTX_free(pctx);   
	EVP_PKEY_free(pkey);



	//cout << "\n--- private key in getRandomID hex : "<< BN_bn2hex(uid) << "\n";


}


string CryptoUtil::char_to_hex(const unsigned char *hash, int size)
{

	stringstream ss;
	for (int i = 0; i < size; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)hash[i];
	}

	string digest = ss.str();
	transform(digest.begin(), digest.end(), digest.begin(), ::toupper);

	return digest;
}

