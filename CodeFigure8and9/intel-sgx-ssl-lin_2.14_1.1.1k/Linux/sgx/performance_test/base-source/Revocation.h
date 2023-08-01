#pragma once

#include "BloomFilter.cpp"
#include "CryptoUtil.cpp"
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
    void updateEpoch(long possible_new_epoch);
    void revokeUID(unsigned char *uidChar, int size, long epoch);
    long get_first_right_node(long epoch_max, long delta, long revoked_delta_index, long& level, long& delta_final);
    void revoke_slot(long epoch, long delta_index, long level, unsigned char* private_k);
    void tree_revoke_walk(long epoch, long epoch_max, long delta, long revoked_delta_index, long level, long last_delta, unsigned char* private_k);
    long getcurrentepoch();
    bool quarantine_check();
    bool verify_revoked_cid_current(unsigned char* uid, long epoch);
    bool verify_revoked_cid_prev(unsigned char* uid, long epoch);    
    bool verify_revoked_slot(unsigned char* sig, long epoch);





}; 