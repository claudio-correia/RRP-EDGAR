#include "Core.h"

void Core::init(int BF_size, int BF_k, long _epoch_fraction, double _delta_fraction) {

    
    epoch_fraction = _epoch_fraction;
    delta_fraction = _delta_fraction;

    cryptoUtil.init();
    epochManager.init(BF_size, BF_k);


}



void Core::close(){
    // Destroy the enclave
    //sgx_destroy_enclave(global_eid);


}


void Core::thread_generate_pseudonym(Pseudonym *pseudonym, int N_pseudonyms, unsigned char* outgoingPseudoBuffer){


    long epoch = epochManager.getcurrentepoch();    
    //cout << "\ncurrent_delta_slot_index: " << current_delta_slot_index << " capability->delta_index_level0: " << capability->delta_index


    if(epoch != pseudonym->epoch){ //se quiser aceitar um intervalo de erro, posso aqui
        print("\n ERROR, os epoch sao diferentes");
        return;
    }


    int ret = cryptoUtil.pseudo_veirfy(pseudonym);
    if(ret != 1){ //se quiser aceitar um intervalo de erro, posso aqui
        print("\n ERROR, in pseudonym verification");
        return;
    }   


    unsigned char uidChar[uid_SIZE];
    cryptoUtil.unseal_pseudonym(pseudonym->sealedData, uidChar);

        
    bool quaratine_completed =  epochManager.quarantine_check();

    if(!quaratine_completed){ 
        print("\n ERROR, in quaratine nor completed");
        return;
    }   



    bool BFcontains = epochManager.verify_revoked_cid_prev(uidChar, pseudonym->epoch - 1);

    if(BFcontains){ 
        print("\n ERROR, user revoked");
        return;
    }   



    BFcontains = epochManager.verify_revoked_cid_current(uidChar, pseudonym->epoch);

    if(BFcontains){ 
        print("\n ERROR, user revoked");
        return;
    }   


    size_t PseuSize = sizeof(struct Pseudonym);
    size_t pseudoBufferSize = PseuSize*N_pseudonyms;
    //unsigned char pseudoBuffer[pseudoBufferSize];
    unsigned char* pseudoBuffer = new unsigned char[pseudoBufferSize];


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
    cryptoUtil.ECDH_key_exchange(shared_secret_sym_key, pseudonym->publicKey, cryptoUtil.magic_enclave_private_key);

    cryptoUtil.aes_gcm_encrypt(pseudoBuffer, pseudoBufferSize, outgoingPseudoBuffer, shared_secret_sym_key);

    delete[] pseudoBuffer;
}






void Core::thread_generate_pseudonym_orlp(Pseudonym *pseudonym, int N_pseudonyms, unsigned char* outgoingPseudoBuffer){


    long epoch = epochManager.getcurrentepoch();    
    //cout << "\ncurrent_delta_slot_index: " << current_delta_slot_index << " capability->delta_index_level0: " << capability->delta_index


    if(epoch != pseudonym->epoch){ //se quiser aceitar um intervalo de erro, posso aqui
        print("\n ERROR, os epoch sao diferentes");
        return;
    }


    int ret = cryptoUtil.pseudo_veirfy_orlp(pseudonym);
    if(ret != 1){ //se quiser aceitar um intervalo de erro, posso aqui
        print("\n ERROR, in pseudonym verification");
        return;
    }   


    unsigned char uidChar[uid_SIZE];
    cryptoUtil.unseal_pseudonym(pseudonym->sealedData, uidChar);

        
    bool quaratine_completed =  epochManager.quarantine_check();

    if(!quaratine_completed){ 
        print("\n ERROR, in quaratine nor completed");
        return;
    }   



    bool BFcontains = epochManager.verify_revoked_cid_prev(uidChar, pseudonym->epoch - 1);

    if(BFcontains){ 
        print("\n ERROR, user revoked");
        return;
    }   



    BFcontains = epochManager.verify_revoked_cid_current(uidChar, pseudonym->epoch);

    if(BFcontains){ 
        print("\n ERROR, user revoked");
        return;
    }   


    size_t PseuSize = sizeof(struct Pseudonym);
    int pseudoBufferSize = PseuSize*N_pseudonyms;
    unsigned char pseudoBuffer[pseudoBufferSize];



    for (long i = 0; i < N_pseudonyms; i++) { 

        Pseudonym*  NewPseudonym = (Pseudonym*)(pseudoBuffer + PseuSize*i);
        epochManager.generatePseudonym_orlp(NewPseudonym, uidChar, epoch + 1, i + 1); //the plus one is to avoid having a zero pseudonim

        /*cout << "\n\n -- New Pseudonym i: " << NewPseudonym->i << "\n";
        cout << " epoch: " << NewPseudonym->epoch << "\n";
        cout<< " sealedData: "<< cryptoUtil.char_to_hex(NewPseudonym->sealedData, 45) << "\n";
        cout<< " publicKey: "<< cryptoUtil.char_to_hex(NewPseudonym->publicKey, 32) << "\n";
        cout<< " Sig: "<< cryptoUtil.char_to_hex(NewPseudonym->Sig, 65) << "\n";*/

    }

    unsigned char shared_secret_sym_key[32]; //only 16 bytes will actualy be use for key material
    cryptoUtil.ECDH_key_exchange(shared_secret_sym_key, pseudonym->publicKey, cryptoUtil.magic_enclave_private_key);

    cryptoUtil.aes_gcm_encrypt(pseudoBuffer, pseudoBufferSize, outgoingPseudoBuffer, shared_secret_sym_key);


}







void Core::thread_generate_pseudonym_haas(int N_pseudonyms, unsigned char* outgoingPseudoBuffer){


    long epoch = epochManager.getcurrentepoch();    
    //cout << "\ncurrent_delta_slot_index: " << current_delta_slot_index << " capability->delta_index_level0: " << capability->delta_index

    //Não estou a verificar o pseudonimo do user, devia???     int ret = cryptoUtil.pseudo_veirfy_orlp(pseudonym);
    /*if(epoch != pseudonym->epoch){ //se quiser aceitar um intervalo de erro, posso aqui
        print("\n ERROR, os epoch sao diferentes");
        return;
    }*/



    int M = 1; // se mudar o valor tenho de mudar certBuffer + CertSize*i 
    //int I = N_pseudonyms; //o mesmo que o I no paper do Haas

    size_t CertSize = sizeof(struct HaaCertificate);
    size_t certBufferSize = CertSize*(M*N_pseudonyms);
    //unsigned char certBuffer[certBufferSize];




    unsigned char* certBufferMyValue = new unsigned char[certBufferSize];

    
    
    unsigned char Si[32];  //a primeira vez o Si funciona como o nonce
    int rc = RAND_bytes(Si, sizeof(Si));


    for (long i = 0; i < N_pseudonyms; i++) { 

        /*print("\n core 21 CertSize: "); printLong(CertSize);
        print("\n core 21 certBufferSize: "); printLong(certBufferSize);
        print("\n core 21 N_pseudonyms: "); printLong( i);*/

        cryptoUtil.hash_function(Si, Si);
        //printHex(" Loop Si: ", Si, 32);
        
        //for (long r = 0; r < M; r++) {  //nao entendo porque é que com este loop deixa de funcionar, mas tbm nao importa
            long r = 0;


            HaaCertificate*  NewCertificate = (HaaCertificate*)(certBufferMyValue + CertSize*i);


            //tbm estou a cagar na chave privada do user, ele devia de a receber de alguma maneira
            cryptoUtil.generate_pub_key_haas(NewCertificate->publicKey);        


            //printHex(" publicKey: ", NewCertificate->publicKey, 32);

            cryptoUtil.aes_gcm_encrypt((unsigned char*)&r, 8, NewCertificate->Esi, Si);
            //printHex(" Esi: ",  NewCertificate->Esi, 20);



            cryptoUtil.pseudo_sign_haas(NewCertificate->Esi, NewCertificate->publicKey, NewCertificate->signature);




        //}

    }

    

    unsigned char Sym_CS[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    cryptoUtil.aes_gcm_encrypt(certBufferMyValue, certBufferSize, outgoingPseudoBuffer, Sym_CS);


    delete[] certBufferMyValue;




}