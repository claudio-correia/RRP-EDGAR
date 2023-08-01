#include "EpochManager.h"


void EpochManager::init(int BF_size, int BF_k){

    cryptoUtil.init();
    revocation.init(BF_size, BF_k); 
}




void EpochManager::generatePseudonym(Pseudonym* pseudonym, unsigned char* uid, long epoch, int i){
    

    
    cryptoUtil.aes_gcm_encrypt(uid, uid_SIZE, pseudonym->sealedData);

    pseudonym->epoch = epoch;
    pseudonym->i = i;

    cryptoUtil.generate_pub_key(uid, pseudonym->epoch, pseudonym->i, pseudonym->publicKey );
	//cout << "private_k : "	<< cryptoUtil.char_to_hex(private_k, 32) << "\n";	


    cryptoUtil.pseudo_sign(pseudonym);


}

void EpochManager::generatePseudonym_orlp(Pseudonym* pseudonym, unsigned char* uid, long epoch, int i){
    

    
    cryptoUtil.aes_gcm_encrypt(uid, uid_SIZE, pseudonym->sealedData);

    pseudonym->epoch = epoch;
    pseudonym->i = i;

    cryptoUtil.generate_pub_key_orlp(uid, pseudonym->epoch, pseudonym->i, pseudonym->publicKey );

    
	//cout << "private_k : "	<< cryptoUtil.char_to_hex(private_k, 32) << "\n";	


    cryptoUtil.pseudo_sign_orlp(pseudonym);


}

long EpochManager::getcurrentepoch(){

    return revocation.getcurrentepoch();

}


bool EpochManager::verify_revoked_cid_current(unsigned char* uid, long epoch)
{
        return revocation.verify_revoked_cid_current(uid, epoch);   
}


bool EpochManager::verify_revoked_cid_prev(unsigned char* uid, long epoch)
{
        return revocation.verify_revoked_cid_prev(uid, epoch);   
}


bool EpochManager::quarantine_check()
{
    return revocation.quarantine_check(); 

}
