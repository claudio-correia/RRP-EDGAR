#include "Revocation.h"

void Revocation::init( int _BF_size, int _BF_k){

    cryptoUtil.init();


    local_current_epoch = 0; //curresponde à posicao 1 do array dos BFs
    BF_size = _BF_size;
    BF_k = _BF_k;

    uidBF[0] =  new BloomFilter(BF_size, BF_k, -1);
    uidBF[1] =  new BloomFilter(BF_size, BF_k, 0);  
    uidBF[2] =  new BloomFilter(BF_size, BF_k, 1);

    deltaBF[0] =  new BloomFilter(BF_size, BF_k, -1);
    deltaBF[1] =  new BloomFilter(BF_size, BF_k, 0);  
    deltaBF[2] =  new BloomFilter(BF_size, BF_k, 1);


    previus_bitmap =  new BloomFilter(500, 1, 0); // to simulate in memory the bitmap, there may be a large number of servers
    previus_bitmap_completed = true;            
    
    //print("E_Revocation \n");


}


bool Revocation::quarantine_check()
{
    return previus_bitmap_completed; 

}



bool Revocation::verify_revoked_cid_current(unsigned char* uid, long epoch)
{

        if(epoch != uidBF[1]->my_epoch){ //se quiser tolerar alguma margem de erro, por aqui
            //cout "\nERROR in verify_revoked_slot, different epoch my_epoch: " << deltaBF[1]->my_epoch << " epoch: "<< epoch <<"\n" ;
            return true;
        }

	    //cout << "\n res: " << deltaBF[1]->possiblyContains(sig, 65*2) <<" sig: " << sig ;

        return uidBF[1]->possiblyContains(uid, 32);

    
}



bool Revocation::verify_revoked_cid_prev(unsigned char* uid, long epoch)
{

        if(epoch != uidBF[0]->my_epoch){ //se quiser tolerar alguma margem de erro, por aqui
            //cout "\nERROR in verify_revoked_slot, different epoch my_epoch: " << deltaBF[1]->my_epoch << " epoch: "<< epoch <<"\n" ;
            return true;
        }

	    //cout << "\n res: " << deltaBF[1]->possiblyContains(sig, 65*2) <<" sig: " << sig ;

        return uidBF[0]->possiblyContains(uid, 32);

    
}
