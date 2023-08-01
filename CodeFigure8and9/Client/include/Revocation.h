#pragma once

#include "BloomFilter.h"
#include "CryptoUtil.h"
#include <math.h>

using namespace std;


class Revocation
{
    public:
    
    int BF_size;
    int BF_k;
    CryptoUtil cryptoUtil;

    BloomFilter *uidBF[3];
    BloomFilter *deltaBF[3];
    BloomFilter *previus_bitmap;

    long local_current_epoch;
    bool previus_bitmap_completed;

    
    void init(int BF_size, int BF_k);
    bool quarantine_check();
    bool verify_revoked_cid_current(unsigned char* uid, long epoch);
    bool verify_revoked_cid_prev(unsigned char* uid, long epoch);




}; 