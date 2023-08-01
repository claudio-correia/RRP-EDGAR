#pragma once

#include <iostream>

using namespace std;
//#include "CryptoUtil.cpp"
#include "EpochManager.cpp"







class Core
{
    CryptoUtil cryptoUtil;
    EpochManager epochManager;
    public:



    void init(int BF_size, int BF_k, long _epoch_fraction, double _delta_fraction);
    void close();    
    void thread_generate_pseudonym(Pseudonym *pseudonym, int N_pseudonyms, unsigned char* outgoingPseudoBuffer);
    void thread_generate_pseudonym_orlp(Pseudonym *pseudonym, int N_pseudonyms, unsigned char* outgoingPseudoBuffer);
    void thread_generate_pseudonym_haas(int N_pseudonyms, unsigned char* outgoingPseudoBuffer);

    /* Epoch controll*/
    long epoch_fraction; 
    double delta_fraction; 

}; 