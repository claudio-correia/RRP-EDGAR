/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#pragma once

//#include "src/ED25519_orlp.h"
#include "../../base-source/Core.cpp"
#include "TestApp.h"
#include "Communication.h"


#include "TestEnclave_u.h"
#include "sgx_urts.h"

#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/opensslv.h>


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>
#include <chrono>
#include <vector>
#include <time.h>


#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <cmath>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/opensslv.h>



# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>


int run_global_enclave = 32;

int job_loop_number = 50;

using namespace std;

//old stuff

vector<double> delays7;
vector<double> delays8;


//#include "TestEnclave_u.h"


class ThreadPool
{
    public:


    ThreadPool (int threads, int N_to_test, int sgx) : shutdown_ (false)
    {
        // Create the specified number of threads
        threads_.reserve (threads);
        for (int i = 0; i < threads; ++i)
            threads_.emplace_back (std::bind (&ThreadPool::threadEntry, this, i, N_to_test, sgx, threads));
    }

    void Kill_ThreadPool ()
    {
        {
            // Unblock any threads and tell them to stop
            std::unique_lock <std::mutex> l (lock_);

            shutdown_ = true;
            condVar_.notify_all();
        }

        // Wait for all threads to stop
        //std::cerr << "Joining threads" << std::endl;
        for (auto& thread : threads_)
            thread.join();
    }

    void doJob (std::function <void (void)> func)
    {
        // Place a job on the queu and unblock a thread
        std::unique_lock <std::mutex> l (lock_);

        jobs_.emplace (std::move (func));
        condVar_.notify_one();
    }

    void write_data(string fileName, vector<double> delays){
        
        string path = "../../../../../../PlotFigures/Figure8/Data/";
        ofstream outfile;

        ifstream f(path + fileName + ".txt");
        int newFile = f.good();// if 1 file exists 0 otherwise

        string command = "touch "+ path + fileName + ".txt";
        system(command.c_str());
        outfile.open(path + fileName + ".txt", ios_base::app);

        if(newFile == 0){
            outfile << to_string(job_loop_number) + "\n";        
        }

        double total = 0;
        double maxValue = 0;
        double minValue = 9999999;


        for (size_t i = 1; i < delays.size(); i++){

            outfile << to_string(delays[i]) + "\n";
            total += delays[i];
            maxValue = max(maxValue,  delays[i]);
            minValue = min(minValue,  delays[i]);
        }

        double mendian = total/delays.size();
        //cout << "\n " << fileName << " median: " << mendian << " max: " << maxValue << " min: " << minValue;
        cout << "\n " << fileName << " MEdian: " << mendian  << " MIn: " << minValue;

        delays.clear();
        outfile.close();
    }

    protected:

    void threadEntry (int i, int N_to_test, int sgx, int threads_in_server)
    {
        std::function <void (void)> job;
        int number_of_jobs =  -100; //0;
        vector<double> delays;
        std::chrono::high_resolution_clock::time_point last_time_point = chrono::high_resolution_clock::now();


        while (1)
        {
            {
                std::unique_lock <std::mutex> l (lock_);

                while (! shutdown_ && jobs_.empty())
                    condVar_.wait (l);

                if (jobs_.empty ())
                {
                    // No jobs to do and we are shutting down
                    //std::cerr << "Thread " << i << " terminates" << std::endl;
                    //std::cerr << "Thread " << i << " terminates number_of_jobs:" << number_of_jobs << std::endl;

                    string filenameString =  "TS_" + std::to_string(threads_in_server) + "_N_" + std::to_string(N_to_test) + "_thread_" + std::to_string(i) ;
    
                    if(sgx == 2 ){
                        filenameString = "SSL_" + filenameString;
                    }else if(sgx == 3) {
                        filenameString = "SSL_SGX_" + filenameString;
                    }else if(sgx == 4) {
                        filenameString = "ORLP_" + filenameString;
                    }else if(sgx == 5) {
                        filenameString = "ORLP_SGX_" + filenameString;
                    }

                    write_data(filenameString, delays);
                    return;
                 }

                //std::cerr << "Thread " << i << " does a job" << std::endl;
                job = std::move (jobs_.front ());
                jobs_.pop();
            }

            // Do the job without holding any locks
            
            job ();
            number_of_jobs++;
            
            if( number_of_jobs % job_loop_number == 0 && number_of_jobs >= 0){ //ignore firt loop
                std::chrono::high_resolution_clock::time_point temporary = last_time_point;
                last_time_point = chrono::high_resolution_clock::now();
                   
                double time = (chrono::duration_cast<chrono::nanoseconds>(last_time_point - temporary).count())*0.000001;               
                delays.push_back(time); 
            }
            

        }

    }

    std::mutex lock_;
    std::condition_variable condVar_;
    bool shutdown_;
    std::queue <std::function <void (void)>> jobs_;
    std::vector <std::thread> threads_;
};


ThreadPool *pool;



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;



/* Error code returned by sgx_create_enclave */

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    //printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(TESTENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }






    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }


    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);


    return 0;
}


void thread_run_function(Core* core, Pseudonym *pseudonym, int N_pseudonyms, int current_request_type, int current_socket){
    
    Communication local_communication = Communication();
    local_communication.init(current_socket);


    size_t PseuSize = sizeof(struct Pseudonym);  
    size_t outgoingPseudoSize = PseuSize*N_pseudonyms + SGX_AESGCM_IV_SIZE;
    //unsigned char outgoingPseudoBuffer[outgoingPseudoSize]; 
    //unsigned char* outgoingPseudoBuffer;

    if(current_request_type == 2 ){
        unsigned char* outgoingPseudoBuffer = new unsigned char[outgoingPseudoSize];
        core->thread_generate_pseudonym(pseudonym, N_pseudonyms, outgoingPseudoBuffer);                
        local_communication.msg_send(outgoingPseudoBuffer, outgoingPseudoSize);
        delete[] outgoingPseudoBuffer;
    
    }else if(current_request_type == 3) {
        unsigned char* outgoingPseudoBuffer = new unsigned char[outgoingPseudoSize];
        sgx_status_t ret = generate_user_pseudonyms(global_eid, (unsigned char*)pseudonym, PseuSize, N_pseudonyms, outgoingPseudoBuffer, outgoingPseudoSize);
        local_communication.msg_send(outgoingPseudoBuffer, outgoingPseudoSize);
        delete[] outgoingPseudoBuffer;
    
    }else if(current_request_type == 4) {
        unsigned char* outgoingPseudoBuffer = new unsigned char[outgoingPseudoSize];
        core->thread_generate_pseudonym_orlp(pseudonym, N_pseudonyms, outgoingPseudoBuffer);                
        local_communication.msg_send(outgoingPseudoBuffer, outgoingPseudoSize);
        delete[] outgoingPseudoBuffer;
    
    }else if(current_request_type == 5) {
        unsigned char* outgoingPseudoBuffer = new unsigned char[outgoingPseudoSize];
        sgx_status_t ret = generate_user_pseudonyms_orlp(global_eid, (unsigned char*)pseudonym, PseuSize, N_pseudonyms, outgoingPseudoBuffer, outgoingPseudoSize);
        local_communication.msg_send(outgoingPseudoBuffer, outgoingPseudoSize);
        delete[] outgoingPseudoBuffer;
    
    }else if(current_request_type == 6) {



        size_t CertSize = sizeof(struct HaaCertificate);
        size_t certBufferSize = CertSize*N_pseudonyms + SGX_AESGCM_IV_SIZE ;
        //unsigned char outgoingCertBuffer[certBufferSize];
        unsigned char* outgoingCertBuffer = new unsigned char[certBufferSize];


        core->thread_generate_pseudonym_haas(N_pseudonyms, outgoingCertBuffer);  
        //cout << "N_pseudonyms: " << N_pseudonyms << "\n";

        local_communication.msg_send(outgoingCertBuffer, certBufferSize);

        
        delete[] outgoingCertBuffer;


    }
    //cout << "a responder devolta ao cliente N_pseudonyms: "<<N_pseudonyms << "\n";    

    //local_communication.msg_send(outgoingPseudoBuffer, outgoingPseudoSize);
    //delete[] outgoingPseudoBuffer;
}


//OCALL
void print_ocall(const char *str)
{
    cout<<str;
}

void printLong_ocall(long value)
{
    cout<<value;
}


string char_to_hex_ocall(const unsigned char *hash, int size)
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




void printHexOcall(const char *str, const unsigned char *hash, size_t size)
{

    cout<<str << char_to_hex_ocall(hash, size) << "\n"; ;

}



void App_generate_user_pseudonyms(  Pseudonym *pseudonym, int N_pseudonyms, unsigned char* outgoingPseudoBuffer){
    


    unsigned char shared_secret_sym_key[32]; //only 16 bytes will actualy be use for key material

    for (long i = 0; i < N_pseudonyms; i++) { 

        unsigned char magic_enclave_private_key[64] = { 0x00, 0xA9, 0x57, 0x27, 0x1E, 0x5A, 0x15, 0xBA, 0x66, 0x25, 0xC0, 0xAF, 0x0C, 0x7D, 0xCC, 0x4F, 0x02, 0xF2, 0xE7, 0xF5, 0x97, 0xD8, 0x0D, 0x63, 0x09, 0x2B, 0x71, 0x07, 0x06, 0x79, 0x57, 0x4C, 0xEB, 0xD2, 0xB7, 0x5F, 0xC5, 0x45, 0xC0, 0xD0, 0x23, 0xA9, 0xBD, 0x59, 0xE0, 0xAD, 0xD2, 0x5B, 0x7F, 0x02, 0xB6, 0xBD, 0x2B, 0xC8, 0xF5, 0x94, 0x57, 0xCF, 0xB7, 0x45, 0x97, 0x7E, 0x20, 0x35};

        ed25519_key_exchange(shared_secret_sym_key, pseudonym->publicKey, magic_enclave_private_key);
    }   

    printHex("fora secret: ", shared_secret_sym_key, 32);
    //core.create_user_pseudonym(NULL, NULL, NULL, NULL, NULL);
    //thread_generate_pseudonym((Pseudonym*)pseudonym, N_pseudonyms, outgoingPseudoBuffer);

    return;

}


void Untrusted_Dacose(){
    

    int N_pseudonyms = run_global_enclave;
    size_t PseuSize = sizeof(struct Pseudonym);
    int pseudoBufferSize = PseuSize*N_pseudonyms;
    int outgoingPseudoSize = pseudoBufferSize + SGX_AESGCM_IV_SIZE;
    unsigned char outgoingPseudoBuffer[outgoingPseudoSize];    
    unsigned char pseudonym_testing[160] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x1A, 0x2A, 0xFB, 0xF8, 0xCE, 0x89, 0xD4, 0x89, 0xBB, 0xC1, 0x4D, 0xF9, 0x57, 0x5F, 0x55, 0x49, 0xD3, 0x16, 0x14, 0x26, 0x74, 0x40, 0x84, 0xBB, 0x76, 0xAF, 0x2C, 0xFB, 0x71, 0xD7, 0xF2, 0x2F, 0x2C, 0x5C, 0x7C, 0xAC, 0xE8, 0xDE, 0x70, 0xCA, 0x7D, 0x26, 0xF3, 0x40, 0x95, 0x07, 0x23, 0x9A, 0xEC, 0x68, 0x93, 0xF0, 0x0F, 0x13, 0xE7, 0xE7, 0xB0, 0x06, 0xDB, 0x70, 0x03, 0xBE, 0x44, 0x0C, 0x8A, 0x69, 0x16, 0x8D, 0xFA, 0x8F, 0x9A, 0xD0, 0x45, 0x40, 0xB2, 0xA6, 0x41, 0x45, 0x2A, 0x79, 0x03, 0x07, 0x03, 0x0B, 0xD5, 0xDD, 0xBF, 0xCD, 0x40, 0x5A, 0x8A, 0x58, 0xFB, 0xA0, 0x7B, 0xE6, 0x04, 0x75, 0x71, 0xA6, 0x04, 0xDD, 0x90, 0x54, 0x08, 0xC9, 0x4B, 0x8A, 0x8D, 0x68, 0x08, 0x13, 0xBB, 0x98, 0x89, 0x90, 0xB8, 0xEC, 0xFE, 0xE1, 0x6B, 0x32, 0x56, 0x6A, 0xCB, 0xC5, 0xF0, 0xF4, 0x47, 0x3C, 0xB4, 0x67, 0x60, 0x40, 0x27, 0x0E, 0x73, 0x34, 0x19, 0x03, 0xDE, 0xFA, 0x58, 0xD7, 0x7F, 0x00, 0x00};
    //App_generate_user_pseudonyms((Pseudonym*)pseudonym_testing, N_pseudonyms, outgoingPseudoBuffer);
    core.thread_generate_pseudonym((Pseudonym*)pseudonym_testing, N_pseudonyms, outgoingPseudoBuffer);



}

void SGX_Dacose(){


    int N_pseudonyms = run_global_enclave;
    size_t PseuSize = sizeof(struct Pseudonym);
    int pseudoBufferSize = PseuSize*N_pseudonyms;
    int outgoingPseudoSize = pseudoBufferSize + SGX_AESGCM_IV_SIZE;
    unsigned char outgoingPseudoBuffer[outgoingPseudoSize];   

    unsigned char pseudonym_testing[160] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x1A, 0x2A, 0xFB, 0xF8, 0xCE, 0x89, 0xD4, 0x89, 0xBB, 0xC1, 0x4D, 0xF9, 0x57, 0x5F, 0x55, 0x49, 0xD3, 0x16, 0x14, 0x26, 0x74, 0x40, 0x84, 0xBB, 0x76, 0xAF, 0x2C, 0xFB, 0x71, 0xD7, 0xF2, 0x2F, 0x2C, 0x5C, 0x7C, 0xAC, 0xE8, 0xDE, 0x70, 0xCA, 0x7D, 0x26, 0xF3, 0x40, 0x95, 0x07, 0x23, 0x9A, 0xEC, 0x68, 0x93, 0xF0, 0x0F, 0x13, 0xE7, 0xE7, 0xB0, 0x06, 0xDB, 0x70, 0x03, 0xBE, 0x44, 0x0C, 0x8A, 0x69, 0x16, 0x8D, 0xFA, 0x8F, 0x9A, 0xD0, 0x45, 0x40, 0xB2, 0xA6, 0x41, 0x45, 0x2A, 0x79, 0x03, 0x07, 0x03, 0x0B, 0xD5, 0xDD, 0xBF, 0xCD, 0x40, 0x5A, 0x8A, 0x58, 0xFB, 0xA0, 0x7B, 0xE6, 0x04, 0x75, 0x71, 0xA6, 0x04, 0xDD, 0x90, 0x54, 0x08, 0xC9, 0x4B, 0x8A, 0x8D, 0x68, 0x08, 0x13, 0xBB, 0x98, 0x89, 0x90, 0xB8, 0xEC, 0xFE, 0xE1, 0x6B, 0x32, 0x56, 0x6A, 0xCB, 0xC5, 0xF0, 0xF4, 0x47, 0x3C, 0xB4, 0x67, 0x60, 0x40, 0x27, 0x0E, 0x73, 0x34, 0x19, 0x03, 0xDE, 0xFA, 0x58, 0xD7, 0x7F, 0x00, 0x00};

    sgx_status_t ret = generate_user_pseudonyms(global_eid, (unsigned char*)pseudonym_testing, PseuSize, N_pseudonyms, outgoingPseudoBuffer, outgoingPseudoSize);
  
}

void crypto_run(int op){


    std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();


    if (op == 7){
        Untrusted_Dacose();
    }else if (op == 8){
        SGX_Dacose();
    }
    
    
    std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
    double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;    
    

    if (op == 7)
    {
        delays7.push_back(time);
    }else if (op == 8)
    {
        delays8.push_back(time);
    }


}

void write_data(string fileName, vector<double> delays)
{


    double total = 0;
    double maxValue = 0;
    double minValue = 9999999;

    for (size_t i = 0; i < delays.size(); i++){

        total += delays[i];
        maxValue = max(maxValue,  delays[i]);
        minValue = min(minValue,  delays[i]);        
    }

    double mendian = total/delays.size();
    cout << "\n " << fileName << " median: " << mendian << " max: " << maxValue << " min: " << minValue;

    delays.clear();
}


void run_performance_test(int complexety, int BF_size, int BF_k, long epoch_fraction, double delta_fraction){

    run_global_enclave = complexety;
    cout << "\n\n test complexety: "<<  run_global_enclave;

    initialize_enclave();

    boot_enclave(global_eid, BF_size, BF_k, epoch_fraction, delta_fraction);



    int run = 2000;
    for (int j = 0; j <= run; j++) {

        crypto_run(7);
        crypto_run(8);

    }


    sgx_destroy_enclave(global_eid);



    write_data("SGX_Dacose              ", delays8);    
    write_data("Untrusted_Dacose        ", delays7);

}


void run_local_performance_test(){

    int BF_size = 10000000;
    int BF_k = 2;
    long epoch_size = 2147483648000000000;
    double delta_fraction = 0.000030517578125;


    core.init(BF_size, BF_k, epoch_size, delta_fraction);


    //para correr um teste local que compara os tempos
    run_performance_test(4, BF_size, BF_k, epoch_size, delta_fraction);
    run_performance_test(8, BF_size, BF_k, epoch_size, delta_fraction);            
    run_performance_test(16,BF_size, BF_k, epoch_size, delta_fraction);    
    run_performance_test(32, BF_size, BF_k, epoch_size, delta_fraction);
    run_performance_test(64, BF_size, BF_k, epoch_size, delta_fraction);

}




void requestHandler(int current_request_type, int current_socket, Core* core) {
    
    //cout << "thread new client\n";

    Communication local_communication = Communication();
    local_communication.init(current_socket);

    bool conected = true;
    while (conected)
    {
        if(current_request_type == 2 || current_request_type == 3  || current_request_type == 4 || current_request_type == 5){ //generate N pseudonims
            int N_pseudonyms = local_communication.read_int(); 
            
            size_t PseuSize = sizeof(struct Pseudonym);  
            Pseudonym pseudonym;
            local_communication.read_buff( (unsigned char *) &pseudonym, PseuSize);


            pool->doJob (std::bind (&thread_run_function, core, &pseudonym, N_pseudonyms, current_request_type, current_socket));        


        }else if (current_request_type == 6)
        {

            Pseudonym pseudonym;
            int N_pseudonyms = local_communication.read_int();         

            pool->doJob (std::bind (&thread_run_function, core, &pseudonym, N_pseudonyms, current_request_type, current_socket));        


        }else if (current_request_type < 0)
        {
            //cout << "closing client\n";
            conected = false;
            break;
        }

        current_request_type = local_communication.read_int(); //next request

    }
    

    local_communication.close_connection(); 



}



void server_handler() {
  

    int BF_size = 10000000;
    int BF_k = 2;
    long epoch_size = 2147483648000000000;
    double delta_fraction = 0.000030517578125;
    int N_to_test = 1;
    int n_threads_in_server = 0;
    Core* current_core = new Core();
    current_core->init(BF_size, BF_k, epoch_size, delta_fraction);

    Communication communication;    
    communication.init();

    initialize_enclave();
    boot_enclave(global_eid, BF_size, BF_k, epoch_size, delta_fraction);
    pool = new ThreadPool(0, 2, 1);


    int current_request_type = 0;
    int current_socket = 0;

    cout << "*PM accepting requests*\n";

    while(communication.wait_request(&current_request_type, &current_socket)){


        if(current_request_type == -1){
            current_core->close();
            pool->Kill_ThreadPool();
            sgx_destroy_enclave(global_eid);
            return;
        }
        else if (current_request_type == 1){ //criar um novo core
            //cout << "request 1\n";


            Communication new_chanel = Communication();
            new_chanel.init(current_socket);

            n_threads_in_server = new_chanel.read_int(); 
            N_to_test = new_chanel.read_int(); 
            int sgx = new_chanel.read_int(); 


            //close
            current_core->close();
            pool->Kill_ThreadPool();
            sgx_destroy_enclave(global_eid);

            //start
            current_core =  new Core();
            current_core->init(BF_size, BF_k, epoch_size, delta_fraction);
            initialize_enclave();
            boot_enclave(global_eid, BF_size, BF_k, epoch_size, delta_fraction);
            pool = new ThreadPool(n_threads_in_server, N_to_test, sgx);


            //cout << "\ncore set, n_threads_in_server: "<< n_threads_in_server << " N_to_test: " << N_to_test <<" \n";            

        }
        else if (current_request_type == 2 || current_request_type == 3  || current_request_type == 4 || current_request_type == 5 || current_request_type == 6)
        {   
            std::thread t1(requestHandler, current_request_type, current_socket, current_core);
            t1.detach();

        }
        



    }


}



/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    (void)(argc);
    (void)(argv);

    /* Changing dir to where the executable is.*/
    char absolutePath[MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]), absolutePath);

    if (ptr == NULL || chdir(absolutePath) != 0)
        return 1;
    
    cout << "\n version outside: "<<  OPENSSL_VERSION_TEXT <<" \n";

    
    //para lancar o server e ficar à espera de pedidos remotos
    server_handler();

    //para correr um teste local que compara os tempos
    //run_local_performance_test();




    cout << "\nClosing app\n\n\n\n\n" << endl;




    return 0;
}
