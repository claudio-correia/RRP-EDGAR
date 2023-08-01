#pragma once

//#include "CryptoUtil.h"
//#include "CryptoUtil.cpp"
#include "Revocation.cpp"


#include <cmath>
#include <tuple>




using namespace std;


class EpochManager
{
    public:
    
   
    CryptoUtil cryptoUtil;
    Revocation revocation;
    
    void init(int BF_size, int BF_k);
    void generatePseudonym(Pseudonym* pseudonym, unsigned char* uid, long epoch, int i);
    void generatePseudonym_orlp(Pseudonym* pseudonym, unsigned char* uid, long epoch, int i);
    long getcurrentepoch();
    bool verify_revoked_cid_current(unsigned char* uid, long epoch);    
    bool verify_revoked_cid_prev(unsigned char* uid, long epoch);   
    bool quarantine_check();
        
}; 