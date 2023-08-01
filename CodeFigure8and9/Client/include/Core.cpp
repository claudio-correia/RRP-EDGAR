
#include "Core.h"





class ThreadPool
{
    public:

    ThreadPool (int threads, int N_to_test) : shutdown_ (false)
    {
        // Create the specified number of threads
        threads_.reserve (threads);
        for (int i = 0; i < threads; ++i)
            threads_.emplace_back (std::bind (&ThreadPool::threadEntry, this, i, N_to_test, threads));
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
        
        ofstream outfile;
        //string fileName = "run_NUC_TH32_min";
        string command = "touch ../../PlotFigures/Figure8/Data/" + fileName + ".txt";
        system(command.c_str());
        outfile.open("../../PlotFigures/Figure8/Data/" + fileName + ".txt", ios_base::app);

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

    protected:

    void threadEntry (int i, int N_to_test, int threads_in_server)
    {
        std::function <void (void)> job;
		int number_of_jobs = 0;
		int job_loop_number = 100;
		vector<double> delays;
		delays.push_back(job_loop_number);
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
			        string filenameString =  "SSL_TS_" + std::to_string(threads_in_server) + "_N_" + std::to_string(N_to_test) + "_thread_" + std::to_string(i) ;
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
			
			if( number_of_jobs % job_loop_number == 0){
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


void Core::init(int n_threads, int N_to_test, long _epoch_fraction, double _delta_fraction, int BF_size, int BF_k)
{
    epoch_fraction = _epoch_fraction;
    delta_fraction = _delta_fraction;
    number_of_threads = n_threads;    
    pool = new ThreadPool(n_threads, N_to_test);

    cryptoUtil.init();
    epochManager.init(BF_size, BF_k, _epoch_fraction, _delta_fraction);

}

void Core::close()
{
    pool->Kill_ThreadPool();
}  


void Core::thread_generate_pseudonym(int client_socket, int N_pseudonyms, Pseudonym *pseudonym){

    Communication local_communication = Communication();
    local_communication.init(client_socket);	


//    cout << "Core thread do work \n";
	int value = 2;
	unsigned char digest[32];

    long epoch = getcurrentepoch();  
	//cout << "\ncurrent_delta_slot_index: " << current_delta_slot_index << " capability->delta_index_level0: " << capability->delta_index
	
	if(epoch != pseudonym->epoch){ //se quiser aceitar um intervalo de erro, posso aqui
		cout << "\n ERROR, os epoch sao diferentes";
		local_communication.msg_send(0);
		return;
	}


    int ret = cryptoUtil.pseudo_veirfy(pseudonym);
	if(ret != 1){ //se quiser aceitar um intervalo de erro, posso aqui
		cout << "\n ERROR, in pseudonym verification";
		local_communication.msg_send(0);
		return;
	}	


    unsigned char uidChar[uid_SIZE];
    cryptoUtil.unseal_pseudonym(pseudonym->sealedData, uidChar);

        
	bool quaratine_completed = epochManager.quarantine_check();

	if(!quaratine_completed){ 
		cout << "\n ERROR, in quaratine nor completed";
		local_communication.msg_send(0);
		return;
	}	



    bool BFcontains = epochManager.verify_revoked_cid_prev(uidChar, pseudonym->epoch - 1);

	if(BFcontains){ 
		cout << "\n ERROR, user revoked";
		local_communication.msg_send(0);
		return;
	}	



    BFcontains = epochManager.verify_revoked_cid_current(uidChar, pseudonym->epoch);

	if(BFcontains){ 
		cout << "\n ERROR, user revoked";
		local_communication.msg_send(0);
		return;
	}	


    size_t PseuSize = sizeof(struct Pseudonym);
    int pseudoBufferSize = PseuSize*N_pseudonyms;
    int outgoingPseudoSize = pseudoBufferSize + SGX_AESGCM_IV_SIZE;
    unsigned char pseudoBuffer[pseudoBufferSize];
    unsigned char outgoingPseudoBuffer[outgoingPseudoSize];



    for (long i = 0; i < N_pseudonyms; i++) { 

    	Pseudonym*  NewPseudonym = (Pseudonym*)(pseudoBuffer + PseuSize*i);
    	epochManager.generatePseudonym(NewPseudonym, uidChar, epoch + 1, i + 1); //the plus one is to avoid having a zero pseudonim

        /*cout << "\n\n -- New Pseudonym i: " << NewPseudonym->i << "\n";
        cout << " epoch: " << NewPseudonym->epoch << "\n";
        cout<< " sealedData: "<< cryptoUtil.char_to_hex(NewPseudonym->sealedData, 45) << "\n";
        cout<< " publicKey: "<< cryptoUtil.char_to_hex(NewPseudonym->publicKey, 32) << "\n";
        cout<< " Sig: "<< cryptoUtil.char_to_hex(NewPseudonym->Sig, 65) << "\n";*/

	}

    unsigned char shared_secret_sym_key[32]; //only 16 bytes will actualy be use for key material
	cryptoUtil.ed25519_key_exchange(shared_secret_sym_key, pseudonym->publicKey, cryptoUtil.magic_enclave_private_key);

    cryptoUtil.aes_gcm_encrypt(pseudoBuffer, pseudoBufferSize, outgoingPseudoBuffer, shared_secret_sym_key);



    local_communication.msg_send(outgoingPseudoBuffer, outgoingPseudoSize);




}

void Core::generate_pseudonym(int client_socket, int N_pseudonyms, Pseudonym *pseudonym){


    pool->doJob (std::bind (&Core::thread_generate_pseudonym, this, client_socket, N_pseudonyms, pseudonym));        



}


unsigned long Core::getcurrentepoch(){
        
    time_point current_time = std::chrono::system_clock::now(); //ter sempre ligado para ter numeos reais

    return 0;
}

