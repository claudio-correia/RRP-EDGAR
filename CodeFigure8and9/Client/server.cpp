#include "Core.h"
#include <thread>

using namespace std;


void requestHandler(int current_request_type, int current_socket, Core* core) {
    
    //cout << "thread new client\n";

    Communication local_communication = Communication();
    local_communication.init(current_socket);

    bool conected = true;
    while (conected)
    {
        if(current_request_type == 2){ //generate N pseudonims
            int N_pseudonyms = local_communication.read_int(); 
            
            size_t PseuSize = sizeof(struct Pseudonym);  
            Pseudonym pseudonym;
            local_communication.read_buff( (unsigned char *) &pseudonym, PseuSize);

            core->generate_pseudonym(current_socket, N_pseudonyms, &pseudonym);

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
    current_core->init(n_threads_in_server, N_to_test, epoch_size, delta_fraction, BF_size, BF_k);

    Communication communication;    
    communication.init();



    int current_request_type = 0;
    int current_socket = 0;

    cout << "*PM accepting requests*\n";

    while(communication.wait_request(&current_request_type, &current_socket)){


        if(current_request_type == -1){
            current_core->close();
            return;
        }
        else if (current_request_type == 1){ //criar um novo core
            //cout << "request 1\n";


            Communication new_chanel = Communication();
            new_chanel.init(current_socket);

            n_threads_in_server = new_chanel.read_int(); 
            N_to_test = new_chanel.read_int(); 


            current_core->close();
            current_core =  new Core();
            current_core->init(n_threads_in_server, N_to_test, epoch_size, delta_fraction, BF_size, BF_k);
            //cout << "\ncore set, n_threads_in_server: "<< n_threads_in_server << " N_to_test: " << N_to_test <<" \n";            

        }
        else if (current_request_type == 2)
        {   

            std::thread t1(requestHandler, current_request_type, current_socket, current_core);
            t1.detach();

        }
        



    }


}



int main()
{

    //basta isto para por a funcionar com o socker
    server_handler();
    cout << "\n\n\n\n\n" << endl;

    return 1;



}


























