//https://stackoverflow.com/questions/26516683/reusing-thread-in-loop-c
#include "CryptoUtil.h"
#include "BloomFilter.h"
#include "Communication.h"

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

vector<double> delays;
typedef std::chrono::system_clock::time_point time_point;


class ThreadPool
{
    public:

    ThreadPool (int threads) : shutdown_ (false)
    {
        // Create the specified number of threads
        threads_.reserve (threads);
        for (int i = 0; i < threads; ++i)
            threads_.emplace_back (std::bind (&ThreadPool::threadEntry, this, i));
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

    protected:

    void threadEntry (int i)
    {
        std::function <void (void)> job;

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
                    return;
                 }

                //std::cerr << "Thread " << i << " does a job" << std::endl;
                job = std::move (jobs_.front ());
                jobs_.pop();
            }

            // Do the job without holding any locks
            job ();
        }

    }

    std::mutex lock_;
    std::condition_variable condVar_;
    bool shutdown_;
    std::queue <std::function <void (void)>> jobs_;
    std::vector <std::thread> threads_;
};




class Core
{
    public:
    CryptoUtil cryptoUtil;
    BloomFilter *deltaBF;

    ThreadPool *pool;
    std::mutex m;
    std::condition_variable cond;
    int slot_sig_size;
    int number_of_threads_finished;
    int result_of_threads;
    long epoch_fraction;
    double delta_fraction;

    void init(int n_threads, int _slot_sig_size, long _epoch_fraction, double _delta_fraction, int BF_size, int BF_k)
    {
        epoch_fraction = _epoch_fraction;
        delta_fraction = _delta_fraction;
        slot_sig_size = _slot_sig_size;    
        pool = new ThreadPool(n_threads);
        number_of_threads_finished = 0; 
        result_of_threads = 1;
        cryptoUtil.init();

        deltaBF =  new BloomFilter(BF_size, BF_k, 0);  

    }

    void close ()
    {
        pool->Kill_ThreadPool();
    }  



    void thread_terminate(int result){

        std::unique_lock<std::mutex> lk{m};    
        //cout << "\nnumber_of_threads_finished: "<< number_of_threads_finished <<"\n"; // incorrect signature 

        if(result != 1){
            result_of_threads = -1;
        }

        number_of_threads_finished++;            
        if(number_of_threads_finished == slot_sig_size){   
            //std::cerr << "Ready to unlock" << std::endl;
            cond.notify_all(); // Notify all waiting threads.
        }        
    }

    bool verify_revoked_slot(unsigned char* sig, long epoch){

            if(epoch != deltaBF->my_epoch){ //se quiser tolerar alguma margem de erro, por aqui
                cout << "\n ERROR in verify_revoked_slot, different epoch my_epoch: " << deltaBF->my_epoch << " epoch: "<< epoch <<"\n" ;
                return true;
            }

            //cout << "\n res: " << deltaBF[1]->possiblyContains(sig, 65*2) <<" sig: " << sig ;

            return deltaBF->possiblyContains(sig, 64);        
    }

    void slot_verify(long epoch, long delta_index, long level,  unsigned char *signature, unsigned char* publicKey){
        
         

        int ret = cryptoUtil.slot_verify( epoch, delta_index,  level, signature, publicKey);

        if (ret != 1) {
            thread_terminate(ret);
            return;
        }



        //verrificar que a assinatura nao esta no BF
        bool BFcontains = verify_revoked_slot(signature, epoch);

        //deixei isto comentado pq  queria avaliar a cena da intro
        //if (BFcontains) {
        //    cout <<  "\n BF revoked"; /* BF contains, revoked*/            
        //    thread_terminate(-1);
        //    return;
        //}


        thread_terminate(1);
    }

    void pseudo_veirfy(Pseudonym* pseudonym){
        

        int ret = cryptoUtil.pseudo_veirfy(pseudonym);

        thread_terminate(ret);
    }    

    void request_veirfy(long request, unsigned char *request_sig, Pseudonym* pseudonym){
        

        int ret = cryptoUtil.request_veirfy(request, request_sig, pseudonym);

        thread_terminate(ret);
    }  

    void write_data(string fileName){
        
        ofstream outfile;
        //string fileName = "run_NUC_TH32_min";
        string command = "touch " + fileName + ".txt";
        system(command.c_str());
        outfile.open( fileName + ".txt", ios_base::app);

        double total = 0;
        double maxValue = 0;
        double minValue = 9999999;


        for (size_t i = 0; i < delays.size(); i++){

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

    int runMultiThread(Capability* capability, long request, unsigned char *request_sig){
            

            long current_delta_slot_index;
            long epoch = getcurrentepoch(current_delta_slot_index);  

            //cout << "\ncurrent_delta_slot_index: " << current_delta_slot_index << " capability->delta_index_level0: " << capability->delta_index_level0;

            if(current_delta_slot_index != capability->delta_index_level0){ //se quiser aceitar um intervalo de erro, posso aqui
                cout << "\n ERROR, os deltas sao diferentes";
                return -1;
            }


            long delta = delta_fraction*epoch_fraction;
            long delta_slot_index = capability->delta_index_level0;
            long delta_left_time = delta_slot_index*delta; //o valor de tempo do lado esquedo da slot, o incio da slot

            long max_level = log2 (1/delta_fraction) + 1;  //calcular a altura da arvore, mais um porque nao sei








            //preparar multithread return
            number_of_threads_finished = 0;    
            result_of_threads = 1;

            

            //pseudo_veirfy
            pool->doJob (std::bind (&Core::pseudo_veirfy, this, &capability->pseudonym));        
            
            //request_veirfy
            pool->doJob (std::bind (&Core::request_veirfy, this, request, request_sig, &capability->pseudonym));        



            for (long i = 1; i <= max_level; i++) { //i = level

                pool->doJob (std::bind (&Core::slot_verify, this, capability->pseudonym.epoch, delta_slot_index,  i, capability->slot_sigs[i].Sig, capability->pseudonym.publicKey));        
       

                delta = delta*2;
                delta_slot_index = delta_left_time/delta;
            }




            //std::cerr << "Threads launched, wiating for them to finish" << std::endl;
            std::unique_lock<std::mutex> lk{m};
            if(number_of_threads_finished < slot_sig_size){
                cond.wait(lk);    
            }

            if(result_of_threads < 1){
                std::cerr << "Pedido rejeitado" << "\n" ;
                return -1;
            }
            return 1;
    }

    unsigned long getcurrentepoch(){
        
        time_point current_time = std::chrono::system_clock::now(); //ter sempre ligado para ter numeos reais

        return 0;
    }

    unsigned long getcurrentepoch(long& delta){
        
        time_point current_time = std::chrono::system_clock::now(); //ter sempre ligado para ter numeos reais

        delta = 0; 

        return 0;
    }

    void admin_get_pseudonym(Pseudonym* pseudonym, unsigned char* uid){ //this fuction shoud comunicate with the enclave, but for evaluation porpuses only we generate the pseudonum localy

        //symetric key to seal data 
        unsigned char Sym_CS[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
        const unsigned char seed[32] = "KGtKgs+0W5/GODnJJS3JvV8MSLDS24A"; //chave privada igual para todos os CSs
        long epoch = getcurrentepoch();
        
        EVP_PKEY *CSKeys = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);



        cryptoUtil.getRandomID(uid);

        
        cryptoUtil.aes_gcm_encrypt(uid, uid_SIZE, pseudonym->sealedData, Sym_CS);

        pseudonym->epoch = epoch;
        pseudonym->i = 0;

        cryptoUtil.generate_pub_key(uid, pseudonym->epoch, pseudonym->i, pseudonym->publicKey);


        cryptoUtil.pseudo_sign(pseudonym, CSKeys);
    }

    void client_create_capability( CapabilityHolder* capabilityHolder, long delta_slot_index, long epoch_size, double delta_fraction) {
       
        //cout << "\n\n----createCapability----- \n"; 


        long delta = delta_fraction*epoch_size;
        //cout << "\nepoch_size: " << epoch_size << " delta " << delta << " delta_slot_index: " << delta_slot_index << "\n";

        //long max_index_for_level = (epoch_size/delta) - 1;  //descobrir o index maximo para um dado nivel da arvore
        //cout << "\nmax_index_for_level_0: " << max_index_for_level;


        long delta_left_time = delta_slot_index*delta; //o valor de tempo do lado esquedo da slot, o incio da slot
        
        
        long tree_base_size = epoch_size/delta;       //ir buscar a quantidade de folhas que a arvore tem
        long max_level = log2 (tree_base_size) + 1;  //calcular a altura da arvore, mais um porque nao sei
        //cout << "\nmax_level " << max_level << " tree_base_size: " << tree_base_size ;

        bool optimization;
        long parallel_delta_index;
        long parallel_delta_left_time;
       
        if(capabilityHolder->capability.delta_index_level0 < 0){ //quando posso aproveitar assinaturas ja feitas
            optimization = false;
            capabilityHolder->capability.slot_sigs = new MySig[max_level+1];
        }else{
            optimization = true;
            parallel_delta_index = capabilityHolder->capability.delta_index_level0;
            parallel_delta_left_time = parallel_delta_index*delta;
        }


        capabilityHolder->capability.slot_size = max_level + 1;
        capabilityHolder->capability.delta_index_level0 = delta_slot_index;




        for (long i = 1; i <= max_level; i++) { //i = level

            if(optimization){
                if(delta_slot_index == parallel_delta_index){
                    //cout << "\n\n----createCapability optimization OUT----- \n"; 
                    return;
                }
                parallel_delta_index = parallel_delta_left_time/(delta*2);

            }
        
            
            cryptoUtil.slot_sign(capabilityHolder->capability.pseudonym.epoch, delta_slot_index, i, capabilityHolder->private_k, capabilityHolder->capability.slot_sigs[i].Sig);
            //cout << "\nsign( index= " << delta_slot_index << ", level= " <<  i << ")  e: " << capabilityHolder->capability.pseudonym.epoch;
            //cout << "\n sig: " << core.cryptoUtil.char_to_hex(capabilityHolder->capability.slot_sigs[i].Sig, 64) << "\n publicKey: " << core.cryptoUtil.char_to_hex(capabilityHolder->capability.pseudonym.publicKey, 32);
            //cout << "\n i: " << i << " sig: " << core.cryptoUtil.char_to_hex(capabilityHolder->capability.slot_sigs[i].Sig, 64);

            
            delta = delta*2;
            delta_slot_index = delta_left_time/delta;

            

        }

        //cout << "\n\n----createCapability OUT----- \n"; 
    }

    void doRunTest(int treeHeight, int n_threads, int n_revoked_users){



        CapabilityHolder capabilityHolder;
        Pseudonym pseudonym;
        unsigned char uid[32];
        long epoch = 0;
        long delta_index = 0;

        admin_get_pseudonym(&capabilityHolder.capability.pseudonym, uid);
        capabilityHolder.capability.delta_index_level0 = -1;  
        cryptoUtil.generate_priv_key( uid, capabilityHolder.capability.pseudonym.i,  capabilityHolder.capability.pseudonym.epoch, capabilityHolder.private_k);

        epoch = getcurrentepoch(delta_index); 
        client_create_capability(&capabilityHolder, delta_index, epoch_fraction, delta_fraction);


        long request = 43;
        unsigned char request_sig[64];  
        cryptoUtil.request_sign(request, capabilityHolder.private_k, request_sig);


        char signature[64] = "asdhjaskdasdhjaskdasdhjaskdfghjasdhjaskdasdhjaskdasdhjaskderty";

        for(int i=0; i<n_revoked_users; i++){ 
            char letters[] = "abcdefghijklmnopqrstuvwxyz";
            signature[rand() % 63] = letters[rand() % 26];
            deltaBF->add((unsigned char *)signature, 64);
        }

        
       for(int i=0; i<10000; i++){ //80000

            std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();

            runMultiThread(&capabilityHolder.capability, request, request_sig);

           std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
           double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;
           
           delays.push_back(time); 

       }

        string filenameString = "revoked_" + std::to_string(n_revoked_users) +  "_test_Tree" + std::to_string(treeHeight) + "_Threads"+ std::to_string(n_threads) ;
       write_data(filenameString );
    }


    void doRunTest(int treeHeight, int n_threads){



        CapabilityHolder capabilityHolder;
        Pseudonym pseudonym;
        unsigned char uid[32];
        long epoch = 0;
        long delta_index = 0;

        admin_get_pseudonym(&capabilityHolder.capability.pseudonym, uid);
        capabilityHolder.capability.delta_index_level0 = -1;  
        cryptoUtil.generate_priv_key( uid, capabilityHolder.capability.pseudonym.i,  capabilityHolder.capability.pseudonym.epoch, capabilityHolder.private_k);

        epoch = getcurrentepoch(delta_index); 
        client_create_capability(&capabilityHolder, delta_index, epoch_fraction, delta_fraction);


        long request = 43;
        unsigned char request_sig[64];  
        cryptoUtil.request_sign(request, capabilityHolder.private_k, request_sig);


        //para apagar
        runMultiThread(&capabilityHolder.capability, request, request_sig);
        return;
        
       for(int i=0; i<10000; i++){ //80000

            std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();

            runMultiThread(&capabilityHolder.capability, request, request_sig);

           std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
           double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;
           
           delays.push_back(time); 

       }

        string filenameString = "test_Tree" + std::to_string(treeHeight) + "_Threads"+ std::to_string(n_threads) ;
       write_data(filenameString );
    }

    int doRunTest( unsigned char * buffer){


        Capability* capability_local = (Capability*)buffer;
        
        size_t CapSize = sizeof(struct Capability); 
        capability_local->slot_sigs = (MySig *)(buffer + CapSize);

        size_t SigsSize = (capability_local->slot_size)*SIG_SIZE_OPENSSL; 
        long* request = (long *) (buffer + CapSize + SigsSize);

        unsigned char* request_sig =  (unsigned char*) (buffer + CapSize + SigsSize + long_size);

        return runMultiThread(capability_local, *request, request_sig);
    }

};





void get_BF_size(double delta_fraction, int& m , int& k){

    long tree_base_size = 1/delta_fraction;       //ir buscar a quantidade de folhas que a arvore tem
    long treeHeight = log2 (tree_base_size) + 1;  //calcular a altura da arvore, mais um porque nao sei

    //cout << "\n no-ceil? treeHeight: " << treeHeight;

    double f = 0.0001/365; //fraction of revocation of f=10−4 per  epoch,
    long c = 250000000; //clients (number of vehicles in the USA)
    long M = 12;
    long p = 1;


    
    long n = f*c*(M+p)*treeHeight; //numero de revocacoes por epoch

    //cout << "\n n: " << n;
    
    //n = 6525; 7*0.0001*250000000*13
    
    
    double FP = 0.001; //taxa de falsos positivos desejados
    m = ceil( -(n*log(FP)) / (pow(log(2),2)) );
    k = ceil( (m/n)*log(2) );
    
}



Core* loadCore(int treeHeight, int n_threads){

    int BF_size = 10000000;
    int BF_k = 2;

    //int n_threads = 2;  
    long epoch_size = 2147483648000000000;
    double delta_fraction = 0.000030517578125;


    if(treeHeight == 2)
        delta_fraction = 0.5;
    if(treeHeight == 4)
        delta_fraction = 0.125;
    if(treeHeight == 8)
        delta_fraction = 0.0078125;
    if(treeHeight == 16)
        delta_fraction = 0.000030517578125;                    
    if(treeHeight == 32)
        delta_fraction = 0.0000000004656612873077392578125; 

    int number_of_parallel_operations = treeHeight + 2; //as outras duas sao veriifcar o pseudonimo e a assinatura do pedido


    //get_BF_size(delta_fraction, BF_size, BF_k);
    //cout << "\n BF_size: " <<  BF_size;

    Core* core = new Core();
    core->init(n_threads, number_of_parallel_operations, epoch_size, delta_fraction, BF_size, BF_k);


    //core.doRunTest(treeHeight, n_threads);

    //core.close();
    return core;
}



void server_handler(){

    int treeHeight = 16;
    int n_threads = 1;

    Core* current_core = loadCore(16, 1); //default core

    Communication communication;
    communication.init();

    int current_request_type = 0;
    int current_socket = 0;

    cout << "*AC accepting requests*\n";

    communication.wait_connection();
    bool conected = true;
    while (conected){
        current_request_type = communication.read_int(); //next request            
        //cout << "connected current_request_type: "<< current_request_type <<" \n";


        if(current_request_type == -1){

            cout << "closing client\n";
            communication.close_connection();            
            conected = false;
            return;

        }
        else if (current_request_type == 1){ //criar um novo core

            treeHeight = communication.read_int(); //next request
            n_threads = communication.read_int(); //next request
            current_core->close();
            current_core = loadCore(treeHeight, n_threads);
            //cout << "new settings treeHeight: "<< treeHeight << " n_threads: " << n_threads <<" \n";            

        }
        else if (current_request_type == 2){ //verificar capability no AC
            
            //cout << "new request\n";
            //int msgSize = communication.read_int();
            size_t CapSize = sizeof(struct Capability);            
            int SigsSize =  (log2 (1/current_core->delta_fraction ) + 1 + 1)*SIG_SIZE_OPENSSL;
            int msgSize = CapSize + SigsSize + long_size + SIG_SIZE_OPENSSL;
            unsigned char buffer[5024] = {0};
            communication.read_buff(buffer, msgSize);
            int ret = current_core->doRunTest(buffer);
            //communication.msg_send(ret);            

            //para apagar
            //current_core->doRunTest(treeHeight,n_threads);
            communication.msg_send(1);            

        }else{

            cout << "request not unkwon\n";
            communication.close_connection();            
            conected = false;
            return;

        }


    }
}


void admin_get_pseudonym2(Pseudonym* pseudonym, unsigned char* uid){ //this fuction shoud comunicate with the enclave, but for evaluation porpuses only we generate the pseudonum localy

    CryptoUtil cryptoUtil;
    cryptoUtil.init();

    //symetric key to seal data 
    unsigned char Sym_CS[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    const unsigned char seed[32] = "KGtKgs+0W5/GODnJJS3JvV8MSLDS24A"; //hash para simular pseudonums revocados
    long epoch = 3L;
    
    EVP_PKEY *CSKeys = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);



    cryptoUtil.getRandomID(uid);

    
    cryptoUtil.aes_gcm_encrypt(uid, uid_SIZE, pseudonym->sealedData, Sym_CS);

    pseudonym->epoch = epoch;
    pseudonym->i = 0;

    cryptoUtil.generate_pub_key(uid, pseudonym->epoch, pseudonym->i, pseudonym->publicKey);


    cryptoUtil.pseudo_sign(pseudonym, CSKeys);
        




    for (int i = 0; i < 200; ++i) {

        ////////////
        //medir tempo
        ////////////
        std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();


        int ret = cryptoUtil.pseudo_veirfy(pseudonym);
        ret = cryptoUtil.pseudo_veirfy(pseudonym); //uma verificacao para o pseudonimo e outra como se fosse o pedido
        unsigned char hash[32];
        cryptoUtil.get_digest(uid, epoch, 0, hash); //simular que calculo a hash do certificado

        //simlar a procura dos pseudonimos numa lista de hashes
        const unsigned char test_seed[32] = "aaaaaa+0W5/GODnJJS3JvV8MSLDS24A"; //simular o pseudonimo nao revocado

        int number_of_pseudonyms = 6000*100; //100 revocados cada um com 6000 pseudonumos, que é o numero de pseudonimos do nosso dataser
        std::vector<unsigned char*> vector_in_memory(number_of_pseudonyms);
        
        for (int i = 0; i < number_of_pseudonyms; ++i) {
            unsigned char* tmp = new unsigned char[32];
            strncpy((char*)tmp, (const char*)seed, 32);        
            char cch = 'a' + rand()%26;
            tmp[0] = cch;
            vector_in_memory[i] = tmp;

        }
            
            
        for (int i = 0; i < number_of_pseudonyms; ++i) {
            //cout << "\n" << i << " : " << vector_in_memory[i];
            
            int result = strcmp((const char*)vector_in_memory[i], (const char*)test_seed);
            
            //if (result==0)
            //    printf(" Strings are equal");
            //else
            //    printf(" Strings are diferent");
       
        }   

        std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
        double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;
        //cout << "\ntime: " << time << " ms";
        delays.push_back(time); 

        ////////////
        //medir tempo
        ////////////

    }

    //write to file
    string fileName = "pki_revocation_check";
    ofstream outfile;
    string command = "touch " + fileName + ".txt";
    system(command.c_str());
    outfile.open( fileName + ".txt", ios_base::app);

    double total = 0;
    double maxValue = 0;
    double minValue = 9999999;


    for (size_t i = 0; i < delays.size(); i++){

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


    //if (ret == 1) {
    //    cout << "\nsignature ok, pseudo_veirfy"; // signature ok
    //} else if (ret == 0) {
    //    cout << "\n ******** incorrect signature, pseudo_veirfy"; // incorrect signature 
    //} else {
    //    cout << "\n  ********* error, pseudo_veirfy"; // error 
    //} 

}



void run_pki_revocation_check(){




//n the dataset, we observed that some taxis drive long distances, requiring 692, 5677, and 32142 pseudonyms per day, month, and year, respectively.


        CapabilityHolder capabilityHolder;

        //symetric key to seal data 
        unsigned char Sym_CS[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
        const unsigned char seed[32] = "KGtKgs+0W5/GODnJJS3JvV8MSLDS24A"; //chave privada igual para todos os CSs
        long epoch = 2;
        unsigned char uid[32];
        Pseudonym pseudonym;

        admin_get_pseudonym2(&capabilityHolder.capability.pseudonym, uid);






}














//correr no mac 
// o server
// rm server; g++ -std=c++11 server.cpp  include/*.cpp -I include/ -lpthread -lssl -lcrypto -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -o server; ./server

// o client
// rm client; g++ -std=c++11 client.cpp  include/*.cpp -I include/ -lpthread -lssl -lcrypto -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -o client; ./client

//corre rno Nuc
// o server
// rm server;  g++ -std=c++11 server.cpp include/*.cpp -I include/ -lssl -lcrypto -lpthread     -o server; ./server

// o client
// rm client;  g++ -std=c++11 client.cpp include/*.cpp -I include/ -lssl -lcrypto -lpthread     -o client; ./client


int main()
{

    //nova versao para o grafico para a intro GS, embora acho que vai para o background agora
    //run_pki_revocation_check();
    //return 1;

    //grafico para a intro GS
    //loadCore(32,1)->doRunTest(32,1, 100);



    //basta isto para por a funcionar com o socker
    server_handler();
    return 1;


    //para funcinar localmente
    loadCore(2,1)->doRunTest(2,1);
    loadCore(4,1)->doRunTest(4,1);
    loadCore(8,1)->doRunTest(8,1);
    loadCore(16,1)->doRunTest(16,1);
    loadCore(32,1)->doRunTest(32,1);

    loadCore(2,2)->doRunTest(2,2);
    loadCore(4,2)->doRunTest(4,2);
    loadCore(8,2)->doRunTest(8,2);
    loadCore(16,2)->doRunTest(16,2);
    loadCore(32,2)->doRunTest(32,2);

    loadCore(2,4)->doRunTest(2,4);
    loadCore(4,4)->doRunTest(4,4);
    loadCore(8,4)->doRunTest(8,4);
    loadCore(16,4)->doRunTest(16,4);
    loadCore(32,4)->doRunTest(32,4);

    loadCore(2,6)->doRunTest(2,6);
    loadCore(4,6)->doRunTest(4,6);
    loadCore(8,6)->doRunTest(8,6);
    loadCore(16,6)->doRunTest(16,6);
    loadCore(32,6)->doRunTest(32,6);

    loadCore(2,8)->doRunTest(2,8);
    loadCore(4,8)->doRunTest(4,8);
    loadCore(8,8)->doRunTest(8,8);
    loadCore(16,8)->doRunTest(16,8);
    loadCore(32,8)->doRunTest(32,8);

    loadCore(2,12)->doRunTest(2,12);
    loadCore(4,12)->doRunTest(4,12);
    loadCore(8,12)->doRunTest(8,12);
    loadCore(16,12)->doRunTest(16,12);
    loadCore(32,12)->doRunTest(32,12);

}


























