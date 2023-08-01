#include "EpochManager.h"


void EpochManager::init(int BF_size, int BF_k, long _epoch_fraction, double _delta_fraction){
    epoch_fraction = _epoch_fraction;
    delta_fraction = _delta_fraction;

    cryptoUtil.init();
    revocation.init(BF_size, BF_k);    
    // int sec, int min, int hour, int day, int mon, int year
    //boot_time = get_clock(0,0,0,1,1,2021); //o primeiro dia as 00:00h, o inicio do primeiro dia


}


void EpochManager::generatePseudonym(Pseudonym* pseudonym, unsigned char* uid, long epoch, int i){
    

    
    cryptoUtil.aes_gcm_encrypt(uid, uid_SIZE, pseudonym->sealedData);

    pseudonym->epoch = epoch;
    pseudonym->i = i;

    cryptoUtil.generate_pub_key(uid, pseudonym->epoch, pseudonym->i, pseudonym->publicKey );
	//cout << "private_k : "	<< cryptoUtil.char_to_hex(private_k, 32) << "\n";	


    cryptoUtil.pseudo_sign(pseudonym);


}


bool EpochManager::quarantine_check()
{
    return revocation.quarantine_check(); 

}



bool EpochManager::verify_revoked_cid_current(unsigned char* uid, long epoch)
{
        return revocation.verify_revoked_cid_current(uid, epoch);   
}


bool EpochManager::verify_revoked_cid_prev(unsigned char* uid, long epoch)
{
        return revocation.verify_revoked_cid_prev(uid, epoch);   
}
