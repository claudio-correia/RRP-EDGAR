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
#include <cstdlib>



using namespace std;

typedef std::chrono::system_clock::time_point time_point;




class Client
{
    public:
    CryptoUtil cryptoUtil;
    Communication communication;

    long epoch_fraction;
    double delta_fraction;


    vector<double> delays2;
    vector<double> delays3;
    vector<double> delaysHaas;
    vector<double> delaysPaper;

   Client(long _epoch_size, double _delta_fraction) {
      

      
        epoch_fraction = _epoch_size;
        delta_fraction = _delta_fraction;
        cryptoUtil.init();
        communication.connect_to("127.0.0.1");
        //communication.connect_to("146.193.41.232"); // Ip do NUC 5
        //communication.connect_to("192.168.1.98"); // Ip do NUC 6


    }



    void run(int N_pseudonyms) {


        int AC_RESQUEST_TYPE = 2;
        communication.msg_send(AC_RESQUEST_TYPE);
        communication.msg_send(N_pseudonyms);

        size_t PseuSize = sizeof(struct Pseudonym);  
        Pseudonym pseudonym;
        unsigned char uid[32];
	    unsigned char magic_pseu_private_key[64]; //this key is the same but in a diferent formart to perform ECC key exanche in DH
        admin_get_pseudonym(&pseudonym, uid);
        cryptoUtil.ed25519_create_keypair( uid, pseudonym.i,  pseudonym.epoch, magic_pseu_private_key); 

        communication.msg_send(&pseudonym, PseuSize);


        int pseudoBufferSize = PseuSize*N_pseudonyms;
        int incomingPseudoSize = pseudoBufferSize + SGX_AESGCM_IV_SIZE;
        unsigned char pseudoBuffer[pseudoBufferSize];
        unsigned char incomingPseudoBuffer[incomingPseudoSize];


        communication.read_buff(incomingPseudoBuffer, incomingPseudoSize);

        unsigned char shared_key_admin[16] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9 }; //mudar esta chave, recebela cifrada
        

        unsigned char shared_secret_sym_key[32]; //only 16 bytes will actualy be use for key material
        cryptoUtil.ed25519_key_exchange(shared_secret_sym_key, cryptoUtil.enclave_public_key, magic_pseu_private_key);
        
        cryptoUtil.aes_gcm_decrypt(incomingPseudoBuffer, 1, pseudoBuffer, pseudoBufferSize, shared_secret_sym_key);


        for (long i = 0; i < N_pseudonyms; i++) { 

            Pseudonym* NewPseudonym = (Pseudonym*) (pseudoBuffer + PseuSize*i);
            
            if(pseudonym.epoch + 1 != NewPseudonym->epoch){
                cout << " Error receiving pseudonyms \n";

            }

            /*cout << "\n\n -- New Pseudonym i: " << NewPseudonym->i << "\n";
            cout << " epoch: " << NewPseudonym->epoch << "\n";
            cout<< " sealedData: "<< cryptoUtil.char_to_hex(NewPseudonym->sealedData, 45) << "\n";
            cout<< " publicKey: "<< cryptoUtil.char_to_hex(NewPseudonym->publicKey, 32) << "\n";
            cout<< " Sig: "<< cryptoUtil.char_to_hex(NewPseudonym->Sig, 65) << "\n";*/


        }

    }

    void run2(int N_pseudonyms, int code_location) {


        communication.msg_send(code_location);
        communication.msg_send(N_pseudonyms);

        size_t PseuSize = sizeof(struct Pseudonym);  
        Pseudonym pseudonym;
        unsigned char uid[32];
        unsigned char magic_pseu_private_key[64]; //this key is the same but in a diferent formart to perform ECC key exanche in DH

    
        if(code_location == 2  || code_location == 3){
            admin_get_pseudonym(&pseudonym, uid);
        }else if(code_location == 4  || code_location == 5) {
            admin_get_pseudonym_orlp(&pseudonym, uid);
        }

        cryptoUtil.ed25519_create_keypair( uid, pseudonym.i,  pseudonym.epoch, magic_pseu_private_key); 


        size_t pseudoBufferSize = PseuSize*N_pseudonyms;
        size_t incomingPseudoSize = pseudoBufferSize + SGX_AESGCM_IV_SIZE;
        unsigned char* pseudoBuffer = new unsigned char[pseudoBufferSize];
        unsigned char* incomingPseudoBuffer = new unsigned char[incomingPseudoSize];

        std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();


        communication.msg_send(&pseudonym, PseuSize);
        communication.read_buff(incomingPseudoBuffer, incomingPseudoSize);



        std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
        double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;    
        

        delaysPaper.push_back(time);


        

        unsigned char shared_secret_sym_key[32]; //only 16 bytes will actualy be use for key material
        cryptoUtil.ed25519_key_exchange(shared_secret_sym_key, cryptoUtil.enclave_public_key, magic_pseu_private_key);
        
        cryptoUtil.aes_gcm_decrypt(incomingPseudoBuffer, 1, pseudoBuffer, pseudoBufferSize, shared_secret_sym_key);


        for (long i = 0; i < N_pseudonyms; i++) { 

            Pseudonym* NewPseudonym = (Pseudonym*) (pseudoBuffer + PseuSize*i);
            
            if(pseudonym.epoch + 1 != NewPseudonym->epoch){
                cout << " Error receiving pseudonyms Dacose\n";

            }

            /*cout << "\n\n -- New Pseudonym i: " << NewPseudonym->i << "\n";
            cout << " epoch: " << NewPseudonym->epoch << "\n";
            cout<< " sealedData: "<< cryptoUtil.char_to_hex(NewPseudonym->sealedData, 45) << "\n";
            cout<< " publicKey: "<< cryptoUtil.char_to_hex(NewPseudonym->publicKey, 32) << "\n";
            cout<< " Sig: "<< cryptoUtil.char_to_hex(NewPseudonym->Sig, 65) << "\n";*/


        }

        delete[] pseudoBuffer;
        delete[] incomingPseudoBuffer;
      

    }



    void run_haas(int N_pseudonyms, int code_location) {


        communication.msg_send(code_location);




        size_t PseuSize = sizeof(struct HaaCertificate);  
        size_t pseudoBufferSize = PseuSize*N_pseudonyms;
        //cout << "pseudoBufferSize: "<< pseudoBufferSize << " N_pseudonyms: " << N_pseudonyms<< " PseuSize: " << PseuSize <<"\n" ;

        size_t incomingPseudoSize = pseudoBufferSize + SGX_AESGCM_IV_SIZE;
        //cout << "incomingPseudoSize: "<< incomingPseudoSize << "\n" ;


        unsigned char* pseudoBuffer = new unsigned char[pseudoBufferSize];
        unsigned char* incomingPseudoBuffer = new unsigned char[incomingPseudoSize];



        std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();


        communication.msg_send(N_pseudonyms);
        communication.read_buff(incomingPseudoBuffer, incomingPseudoSize);



        std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
        double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;    
        

        delaysHaas.push_back(time);
        


        

        unsigned char Sym_CS[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

        cryptoUtil.aes_gcm_decrypt(incomingPseudoBuffer, 1, pseudoBuffer, pseudoBufferSize, Sym_CS);


        for (long i = 0; i < N_pseudonyms; i++) { 

            HaaCertificate* NewPseudonym = (HaaCertificate*) (pseudoBuffer + PseuSize*i);
            
            //cout<< " publicKey: "<< cryptoUtil.char_to_hex(NewPseudonym->publicKey, 32) << "\n";



        }
      
        delete[] pseudoBuffer;
        delete[] incomingPseudoBuffer;      

    }



    void write_data(string fileName, vector<double> delays)
    {


        string path = "../../PlotFigures/Figure9/Data/";
        ofstream outfile;

        ifstream f(path + fileName + ".txt");
        int newFile = f.good();// if 1 file exists 0 otherwise

        string command = "touch "+ path + fileName + ".txt";
        system(command.c_str());
        outfile.open(path + fileName + ".txt", ios_base::app);



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
        cout << "\n " << fileName << " median: " << mendian << " max: " << maxValue << " min: " << minValue;

        delays.clear();
        outfile.close();
    
    }


    void close(){
        communication.msg_send(-1); //close connection
        communication.close_connection();

    }

    void close(int code_location){
        communication.msg_send(-1); //close connection
        communication.close_connection();

        /*if (code_location == 2){
            write_data("Untrusted_Dacose        ", delays2);
        }else if (code_location == 3){
            write_data("SGX_Dacose              ", delays3);    
        }*/


    }

    void close_server(){
        communication.msg_send(-1); //close connection
        communication.close_connection();
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

    void admin_get_pseudonym_orlp(Pseudonym* pseudonym, unsigned char* uid){ //this fuction shoud comunicate with the enclave, but for evaluation porpuses only we generate the pseudonum localy


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


        unsigned char public_key[32];
        unsigned char private_key[64];
        cryptoUtil.ed25519_create_keypair(public_key, private_key, seed);




        cryptoUtil.pseudo_sign_orlp(pseudonym, public_key, private_key);
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


};


void run_client_generate_pseudonym(int N_pseudonyms, int work){
    
    long epohc_fraction = 2147483648000000000; //86400000000000 valor em que um epoch é um dia -> 122880000000000 é 34hours mas é tem base de 2 para poder ter uma arvore binaria perfeita para as contas baterem certas
    double delta_fraction = 0.000030517578125; // 0.000694 valor de delta por min -> 1min fraccao das 34h 0.00048828125

    Client client = Client(epohc_fraction, delta_fraction);

    for (long i = 1; i <= work; i++) { 
        client.run(N_pseudonyms);
    }

    client.close();

}




void eval_generate_pseudonym(int server_threads, int number_of_client_threads, int N_pseudonyms, int work){
    


    Client boot_server = Client(0, 0);
    boot_server.communication.msg_send(1);
    boot_server.communication.msg_send(server_threads);
    boot_server.communication.msg_send(N_pseudonyms);
    boot_server.close();

    std::vector<std::thread> vecOfThreads;

    for (long i = 1; i <= number_of_client_threads; i++) { 
        std::thread t1(run_client_generate_pseudonym, N_pseudonyms, work);
        vecOfThreads.push_back(std::move(t1));
    }



    // Iterate over the thread vector
    for (std::thread & th : vecOfThreads)
    {
        // If thread Object is Joinable then Join that thread.
        if (th.joinable())
            th.join();
    }


    

}




void run_client_generate_pseudonym2(int N_pseudonyms, int work, int code_location){
    
    long epohc_fraction = 2147483648000000000; //86400000000000 valor em que um epoch é um dia -> 122880000000000 é 34hours mas é tem base de 2 para poder ter uma arvore binaria perfeita para as contas baterem certas
    double delta_fraction = 0.000030517578125; // 0.000694 valor de delta por min -> 1min fraccao das 34h 0.00048828125

    Client client = Client(epohc_fraction, delta_fraction);

    for (long i = 1; i <= work; i++) { 
        client.run2(N_pseudonyms, code_location);
    }

    client.close(code_location);

}


void eval_generate_pseudonym2(int server_threads, int number_of_client_threads, int N_pseudonyms, int work, int code_location){
    


    Client boot_server = Client(0, 0);
    boot_server.communication.msg_send(1);
    boot_server.communication.msg_send(server_threads);
    boot_server.communication.msg_send(N_pseudonyms);
    boot_server.communication.msg_send(code_location);    
    boot_server.close();

    std::vector<std::thread> vecOfThreads;

    for (long i = 1; i <= number_of_client_threads; i++) { 
        std::thread t1(run_client_generate_pseudonym2, N_pseudonyms, work, code_location);
        vecOfThreads.push_back(std::move(t1));
    }



    // Iterate over the thread vector
    for (std::thread & th : vecOfThreads)
    {
        // If thread Object is Joinable then Join that thread.
        if (th.joinable())
            th.join();
    }


    

}



void eval_2(int server_threads, int number_of_client_threads, int N_pseudonyms, int work, int type){
    



    cout << "\n\n complexity: " << N_pseudonyms;    

    if( type == 3){
        /// No SGX evaluation
        eval_generate_pseudonym2(server_threads, number_of_client_threads, N_pseudonyms, work,2);
    }

    if( type == 1){    
        /// SGX evaluation
        eval_generate_pseudonym2(server_threads, number_of_client_threads, N_pseudonyms, work,3);
        eval_generate_pseudonym2(server_threads, number_of_client_threads, N_pseudonyms, work,5);
    }
    

}

void run_experiment(int type){
    

    int multiplier_of_clients = 4;
    int number_of_client_threads = 3;
    int server_threads = 1;
    int work = 100;  //1000      // numero de pedidos que cada cliente faz, "para pedir N pseudonimos"



    server_threads = 1;
    number_of_client_threads = multiplier_of_clients*server_threads;    
    eval_2(server_threads, number_of_client_threads, 2, work, type);
    eval_2(server_threads, number_of_client_threads, 4, work, type);
    eval_2(server_threads, number_of_client_threads, 8, work, type);
    eval_2(server_threads, number_of_client_threads, 16, work, type);
    eval_2(server_threads, number_of_client_threads, 32, work, type);

    server_threads = 2;
    number_of_client_threads = multiplier_of_clients*server_threads;    
    eval_2(server_threads, number_of_client_threads, 2, work, type);
    eval_2(server_threads, number_of_client_threads, 4, work, type);
    eval_2(server_threads, number_of_client_threads, 8, work, type);
    eval_2(server_threads, number_of_client_threads, 16, work, type);
    eval_2(server_threads, number_of_client_threads, 32, work, type);

    server_threads = 4;
    number_of_client_threads = multiplier_of_clients*server_threads;    
    eval_2(server_threads, number_of_client_threads, 2, work, type);
    eval_2(server_threads, number_of_client_threads, 4, work, type);
    eval_2(server_threads, number_of_client_threads, 8, work, type);
    eval_2(server_threads, number_of_client_threads, 16, work, type);
    eval_2(server_threads, number_of_client_threads, 32, work, type);


    server_threads = 6;
    number_of_client_threads = multiplier_of_clients*server_threads;    
    eval_2(server_threads, number_of_client_threads, 2, work, type);
    eval_2(server_threads, number_of_client_threads, 4, work, type);
    eval_2(server_threads, number_of_client_threads, 8, work, type);
    eval_2(server_threads, number_of_client_threads, 16, work, type);
    eval_2(server_threads, number_of_client_threads, 32, work, type);

    

}

void run_IS_get_pseudonyms(int type){
    
    cout << "Hello from client" << endl;

    run_experiment(type);

    cout << " run_experiment done" << endl;

    run_experiment(type);
    run_experiment(type);
    run_experiment(type);
    run_experiment(type);
    //run_experiment(type);
    //run_experiment(type);
    //run_experiment(type);
    //run_experiment(type);
    //run_experiment(type);
    //run_experiment(type);
    //run_experiment(type);

            
    Client server_killer2 = Client(0, 0);
    server_killer2.close_server();



}




void eval_haas(int  N_pseudonyms, int haas_N_pseudonyms, int dacose, string period){
    
    int server_threads = 2;
    int work = 5; //200        // numero de pedidos que cada cliente faz, "para pedir N pseudonimos"

    Client boot_server = Client(0, 0);
    boot_server.communication.msg_send(1);
    boot_server.communication.msg_send(server_threads);
    boot_server.communication.msg_send(N_pseudonyms);
    boot_server.close();


    long epohc_fraction = 2147483648000000000; //86400000000000 valor em que um epoch é um dia -> 122880000000000 é 34hours mas é tem base de 2 para poder ter uma arvore binaria perfeita para as contas baterem certas
    double delta_fraction = 0.000030517578125; // 0.000694 valor de delta por min -> 1min fraccao das 34h 0.00048828125

    Client client = Client(epohc_fraction, delta_fraction);


    for (long i = 1; i <= work; i++) { 
        //cout << "\nwork " << i << endl;

        if(dacose>0)
            client.run2(N_pseudonyms, 3);
        client.run_haas(haas_N_pseudonyms, 6);

    }

    client.close();

    client.write_data("Haas_" + to_string(haas_N_pseudonyms) + period, client.delaysHaas);
    
    if(dacose>0)
        client.write_data("Dacose_" + to_string(N_pseudonyms) + period, client.delaysPaper);

}

//Dacose -> Dacose_1146_day, Dacose_26358_month, Dacose_316296_year
//Haas day -> Haas_ _day [  4584.   4584.   4584.   4584.   5760.  17280. 172800.]
//Haas month -> Haas_ _month  [ 105432.   105432.   105432.   105432.   175316.4  525949.2 5259492. ]
//Haas year -> Haas_ _year [ 1265184.   1265184.   1265184.   1265184.   2103796.8  6311390.4 63113904. ]
//novos valores
     
 // [  692.  1504.  2848.  2928.  3072.  5760.  7680.  8640. 28800.]
 //   [  7020.7725  45777.06    86684.22    89119.17    93502.08   175316.4  233755.2    262974.6    876582.    ]
 //   [   84249.27   549324.72  1040210.64  1069430.04  1122024.96  2103796.8 2805062.4   3155695.2  10518984.  ]
void run_haas_comparation(){

    eval_haas(692, 692, 1, "_day");
    eval_haas(1, 1504, 0, "_day");
    eval_haas(1, 2848, 0, "_day");
    eval_haas(1, 2928, 0, "_day");
    eval_haas(1, 3072, 0, "_day");
    eval_haas(1, 5760, 0, "_day");
    eval_haas(1, 7680, 0, "_day");
    eval_haas(1, 8640, 0, "_day");
    eval_haas(1, 28800, 0, "_day");


    eval_haas(5677, 7020, 1, "_month");
    eval_haas(1, 45777, 0, "_month");//nao vale apena correr a msm coisa 3 vezes
    eval_haas(1, 86684, 0, "_month");
    eval_haas(1, 89119, 0, "_month");
    eval_haas(1, 93502, 0, "_month");
    eval_haas(1, 175316, 0, "_month");
    eval_haas(1, 233755, 0, "_month");
    eval_haas(1, 262974, 0, "_month");
    eval_haas(1, 876582, 0, "_month");

    eval_haas(32142, 84249, 1, "_year");
    eval_haas(1, 549324, 0, "_year"); //nao vale apena correr a msm coisa 3 vezes
    eval_haas(1, 1040210, 0, "_year");
    eval_haas(1, 1069430, 0, "_year");
    eval_haas(1, 1122024, 0, "_year");
    eval_haas(1, 2103796, 0, "_year");
    eval_haas(1, 2805062, 0, "_year");
    eval_haas(1, 3155695, 0, "_year");
    eval_haas(1, 10518984, 0, "_year");

                 
    Client server_killer2 = Client(0, 0);
    server_killer2.close_server();
}



int main(int argc, char** argv)
{





    int client_experiment = 0;
    if(argc>1){
        client_experiment = atoi(argv[1]);
    }


    switch (client_experiment) {
    case 1:
        cout << "Running run_PM_get_pseudonyms experiemnt.\n";
        run_IS_get_pseudonyms(1);
        break;
    case 2:
        cout << "\nRunning run_haas_comparation experiemnt.\n";
        run_haas_comparation();
        break;
    case 3:
        cout << "Running run_PM_get_pseudonyms experiemnt No SGX.\n";
        run_IS_get_pseudonyms(3);
        break;        
    }    

    cout << "\n\n\n\n\n" << endl;




}


























