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



using namespace std;

vector<double> delays;
typedef std::chrono::system_clock::time_point time_point;




class Client
{
    public:
    CryptoUtil cryptoUtil;
    Communication communication;

    long epoch_fraction;
    double delta_fraction;


   Client(long _epoch_size, double _delta_fraction) {
      

      
        epoch_fraction = _epoch_size;
        delta_fraction = _delta_fraction;
        cryptoUtil.init();
        communication.connect_to("127.0.0.1");
        //communication.connect_to("146.193.41.232"); //NUC 6


    }


    void write_data(string fileName){
        ofstream outfile;
        //string fileName = "run_NUC_TH32_min";
        string command = "touch ../PlotFigures/Figure7/Data/" + fileName + ".txt";
        system(command.c_str());
        outfile.open("../PlotFigures/Figure7/Data/" + fileName + ".txt", ios_base::app);

        double total = 0;
        double maxValue = 0;
        double minValue = 9999999;


        for (size_t i = 0; i < delays.size(); i++){

            outfile << to_string(delays[i]) + "\n";
            total += delays[i];
            maxValue = max(maxValue,  delays[i]);
            minValue = min(minValue,  delays[i]);
        }

        double mean = total/delays.size();
        cout << "\n " << fileName << " Mean: " << mean  << " MIn: " << minValue  << " MAx: " << maxValue;
        //cout << "\n "  << " total: " << total << " delays.size(): " << delays.size();


        delays.clear();
        outfile.close();
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

    void send_AC_request(Capability* capability, long request, unsigned char* request_sig) {

        
        //to send-> cap + Sig[array] + request (int) + request Sig
        size_t CapSize = sizeof(struct Capability);
        size_t SigsSize = (capability->slot_size)*SIG_SIZE_OPENSSL; 
        int msgsize = CapSize + SigsSize + long_size + SIG_SIZE_OPENSSL;

        int AC_RESQUEST_TYPE = 2;
        communication.msg_send(AC_RESQUEST_TYPE);
        //communication.msg_send(msgsize);
//
        //communication.msg_send(capability, CapSize);
        //communication.msg_send(capability->slot_sigs, SigsSize);
        //communication.msg_send(&request, long_size);
        //communication.msg_send(request_sig, SIG_SIZE_OPENSSL);


        if(communication.read_int() == 1){
            //cout << "request accepted\n";
        }else
        {
            cout << "request rejected\n";
        }

    }

    void send_AC_request(unsigned char *buffer, int msgsize) {


        int AC_RESQUEST_TYPE = 2;
        communication.msg_send(AC_RESQUEST_TYPE);
        //communication.msg_send(msgsize);

        communication.msg_send(buffer, msgsize);



        if(communication.read_int() == 1){
            //cout << "request accepted\n";
        }else
        {
            cout << "request rejected\n";
        }

    }

    void change_settings(int treeHeight, int n_threads){

        communication.msg_send(1); //para mudar as cenas do Core
        communication.msg_send(treeHeight); 
        communication.msg_send(n_threads); 

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

    }


    void AC_eva( int treeHeight, int n_threads){
        

        change_settings(treeHeight, n_threads);



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



        //copiar tudo para um socket para evitar ter que mandar vaias mensagens na rede para um pedido apenas
        unsigned char buffer[5024] = {0};
        size_t CapSize = sizeof(struct Capability);
        size_t SigsSize = (capabilityHolder.capability.slot_size)*SIG_SIZE_OPENSSL;
        int msgsize = CapSize + SigsSize + long_size + SIG_SIZE_OPENSSL;
        memcpy(buffer, &capabilityHolder.capability, CapSize);
        memcpy(buffer + CapSize, capabilityHolder.capability.slot_sigs, SigsSize);
        memcpy(buffer + CapSize + SigsSize, &request, long_size);
        memcpy(buffer + CapSize + SigsSize + long_size, request_sig, SIG_SIZE_OPENSSL);



        int run = 1000; //10000

        for (int j = 0; j <= run; j++) { //43576

            std::chrono::high_resolution_clock::time_point operationStart = chrono::high_resolution_clock::now();

            send_AC_request(buffer,msgsize);
            
            std::chrono::high_resolution_clock::time_point end = chrono::high_resolution_clock::now();
            double time = (chrono::duration_cast<chrono::nanoseconds>(end - operationStart).count())*0.000001;
            

            delays.push_back(time); 
        }

        string filename  = "test_Tree" + std::to_string(treeHeight) + "_Threads"+ std::to_string(n_threads) ;
        write_data(filename);

    }


    void close(){
        communication.msg_send(-1); //close connection
        communication.close_connection();
    }

};





int main()
{

    long epohc_fraction = 2147483648000000000; //86400000000000 valor em que um epoch é um dia -> 122880000000000 é 34hours mas é tem base de 2 para poder ter uma arvore binaria perfeita para as contas baterem certas
    double delta_fraction = 0.000030517578125; // 0.000694 valor de delta por min -> 1min fraccao das 34h 0.00048828125
    int M = 1;  //maximum number of pseudonyms per epoch
    int treeHeight = 16;
    int n_threads = 1;

    cout << "Hello from client" << endl;



    Client client = Client(epohc_fraction, delta_fraction);

    client.AC_eva(2, 1);
    client.AC_eva(4, 1);
    client.AC_eva(8, 1);
    client.AC_eva(16, 1);
    client.AC_eva(32, 1);

    client.AC_eva(2, 2);
    client.AC_eva(4, 2);
    client.AC_eva(8, 2);
    client.AC_eva(16, 2);
    client.AC_eva(32, 2);

    client.AC_eva(2, 4);
    client.AC_eva(4, 4);
    client.AC_eva(8, 4);
    client.AC_eva(16, 4);
    client.AC_eva(32, 4);

    client.AC_eva(2, 6);
    client.AC_eva(4, 6);
    client.AC_eva(8, 6);
    client.AC_eva(16, 6);
    client.AC_eva(32, 6);

    client.AC_eva(2, 8);
    client.AC_eva(4, 8);
    client.AC_eva(8, 8);
    client.AC_eva(16, 8);
    client.AC_eva(32, 8);


    client.AC_eva(2, 12);
    client.AC_eva(4, 12);
    client.AC_eva(8, 12);
    client.AC_eva(16, 12);
    client.AC_eva(32, 12);


    client.close();
    cout << "\n\n\n\n\n" << endl;



}


























