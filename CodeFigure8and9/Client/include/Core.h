//https://stackoverflow.com/questions/26516683/reusing-thread-in-loop-c
#pragma once

#include "CryptoUtil.h"
#include "Communication.h"
#include "EpochManager.h"

#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <chrono>
#include <cmath>
#include <vector>
#include <fstream>

#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

using namespace std;

typedef std::chrono::system_clock::time_point time_point;   

class Core
{
    public:
    
    vector<double> delays;
    CryptoUtil cryptoUtil;
    EpochManager epochManager;

    int number_of_threads;
    long epoch_fraction;
    double delta_fraction;

    void init(int n_threads, int N_to_test, long _epoch_fraction, double _delta_fraction, int BF_size, int BF_k);
    void generate_pseudonym(int client_socket, int N_pseudonyms, Pseudonym *pseudonym);
    void thread_generate_pseudonym(int client_socket, int N_pseudonyms, Pseudonym *pseudonym);
    unsigned long getcurrentepoch();
    void close();



}; 