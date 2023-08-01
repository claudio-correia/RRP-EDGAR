#pragma once

#include "CryptoUtil.h"
#include "Revocation.h"

#include <cmath>
#include <tuple>




using namespace std;


class EpochManager
{
    public:
    
    long epoch_fraction; 
    double delta_fraction;    
    CryptoUtil cryptoUtil;
    Revocation revocation;

    void init( int BF_size, int BF_k, long epoch_fraction, double delta_fraction);
    void generatePseudonym(Pseudonym* pseudonym, unsigned char* uid, long epoch, int i);
    bool quarantine_check();
    bool verify_revoked_cid_current(unsigned char* uid, long epoch);    
    bool verify_revoked_cid_prev(unsigned char* uid, long epoch);


}; 