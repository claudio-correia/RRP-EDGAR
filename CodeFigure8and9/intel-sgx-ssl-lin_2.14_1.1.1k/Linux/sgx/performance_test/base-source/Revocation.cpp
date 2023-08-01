#include "Revocation.h"

void Revocation::init( int _BF_size, int _BF_k){

    cryptoUtil.init();


    local_current_epoch = 0; //curresponde à posicao 1 do array dos BFs
    BF_size = _BF_size;
    BF_k = _BF_k;

    uidBF[0] =  new BloomFilter(BF_size, BF_k, -1);
    uidBF[1] =  new BloomFilter(BF_size, BF_k, 0);  
    uidBF[2] =  new BloomFilter(BF_size, BF_k, 1);

    deltaBF[0] =  new BloomFilter(BF_size, BF_k, -1);
    deltaBF[1] =  new BloomFilter(BF_size, BF_k, 0);  
    deltaBF[2] =  new BloomFilter(BF_size, BF_k, 1);

    previus_bitmap =  new BloomFilter(500, 1, 0); // to simulate in memory the bitmap, there may be a large number of servers
    previus_bitmap_completed = true; 
    
    //print("Revocation \n");


}

long Revocation::getcurrentepoch(){
    return local_current_epoch;
}

bool Revocation::quarantine_check()
{
    return previus_bitmap_completed; 

}

bool Revocation::verify_revoked_cid_current(unsigned char* uid, long epoch)
{

        if(epoch != uidBF[1]->my_epoch){ //se quiser tolerar alguma margem de erro, por aqui
            //cout "\nERROR in verify_revoked_slot, different epoch my_epoch: " << deltaBF[1]->my_epoch << " epoch: "<< epoch <<"\n" ;
            return true;
        }

	    //cout << "\n res: " << deltaBF[1]->possiblyContains(sig, 65*2) <<" sig: " << sig ;

        return uidBF[1]->possiblyContains(uid, 32);

    
}



bool Revocation::verify_revoked_cid_prev(unsigned char* uid, long epoch)
{

        if(epoch != uidBF[0]->my_epoch){ //se quiser tolerar alguma margem de erro, por aqui
            //cout "\nERROR in verify_revoked_slot, different epoch my_epoch: " << deltaBF[1]->my_epoch << " epoch: "<< epoch <<"\n" ;
            return true;
        }

	    //cout << "\n res: " << deltaBF[1]->possiblyContains(sig, 65*2) <<" sig: " << sig ;

        return uidBF[0]->possiblyContains(uid, 32);

    
}



 void Revocation::revokeUID(unsigned char *uidChar, int size, long epoch){

    if(epoch != uidBF[1]->my_epoch)
        print("ERROR in revokeUID");

    uidBF[1]->add(uidChar, size);

 }

void Revocation::revoke_slot(long epoch, long delta_index, long level, unsigned char* private_k)
{

        unsigned char sig[SIG_EdDSA_SIZE];
        cryptoUtil.slot_sign(epoch, delta_index, level, private_k, sig);

        if(epoch != deltaBF[1]->my_epoch)
            print("ERROR in revoke_slot");
        
        deltaBF[1]->add(sig, SIG_EdDSA_SIZE);


        //bool res = deltaBF[1]->possiblyContains(sig, SIG_EdDSA_SIZE);
	    //cout << "\n res: " << res << " sigx: " << sig ;

    
}


void Revocation::tree_revoke_walk(long epoch, long epoch_max, long delta, long revoked_delta_index, long level, long last_delta, unsigned char* private_k)
{

    //cout << "\ntree_revoke_walk( epoch_max= " << epoch_max << ", delta= " <<  delta <<", revoked_delta_index= " <<  revoked_delta_index <<", level= " <<  level <<", last_delta= " <<  last_delta << ")";

    long max_index_for_level = (epoch_max/last_delta) - 1;  //descobrir o index maximo para um dado nivel da arvore
    
    long current_delta_index = revoked_delta_index;
    long delta_left = current_delta_index*last_delta; //o valor de tempo do lado esquedo da slot, o incio da slot
    
    //cout << "\nWhile( current_delta_index= " << current_delta_index << ", max_index_for_level= " << max_index_for_level<<", level= " <<  level << ")";

    
    while(max_index_for_level > current_delta_index){ //enquanto eu nao chegar ao slot mais á esquerda da arvore
        
        level = level + 1;
        last_delta = last_delta*2;
        current_delta_index = delta_left/last_delta;
        
	    //cout << "\nWhile( current_delta_index= " << current_delta_index << ", level= " <<  level << ")";
        
        if((current_delta_index )%2==0){ //quando é um node de esquerda, subir a arvore ate encontar
            
            
            current_delta_index = current_delta_index + 1;
            //revoke(current_delta_index, last_delta)
            
            revoke_slot(epoch, current_delta_index, level, private_k);
	        //cout << "\nrevoke( delta index= " << current_delta_index << ", level= " <<  level << ") epoch =" << epoch;

            delta_left = current_delta_index*last_delta;
            

        }
        
        max_index_for_level = (epoch_max/last_delta) - 1;   
	    //cout << "\n end ( max_index_for_level= " << max_index_for_level << ", current_delta_index= " <<  current_delta_index << ")";
        
    }



    
}


long Revocation::get_first_right_node(long epoch_max, long delta, long revoked_delta_index, long& level, long& delta_final)
{

    long delta_left = revoked_delta_index*delta; //ir buscar o valor de tempo relatico ao inicio do slot
    long tree_base_size = epoch_max/delta;       //ir buscar a quantidade de folhas que a arvore tem
    long max_level = log2 (tree_base_size) + 1;  //calcular a altura da arvore, mais um porque nao sei
    //cout << "\nmax_level " << max_level;
        
    if(revoked_delta_index == 0){   //caso em que a slot é a primeira da arvore, entao basta revocar a root
        level = max_level;          //a root esta no nivel maximo 
        delta_final = epoch_max;        //o intervalo é o epoch inteiro
        return revoked_delta_index;
    }    
    
    level = 1;
    while((revoked_delta_index + 1 )%2!=0){ //talvez seja possivel fazer isto sem o ciclo // subir a arvore á procura do primeiro node que é um filho da direita
        
        level = level + 1;                      //para saber em que nivel estamos, altura da arvore
        delta = delta*2;                        //para saber o intervalo do slot em que estamos, vai aumentando logarimitcamente com a altura da arvore
        revoked_delta_index = delta_left/delta; //sabendo o ponto revokado, qual o indec correspondente para este nivel da arvore

    }
    
    delta_final = delta;
    
    return revoked_delta_index;
    
}


 void Revocation::updateEpoch(long possible_new_epoch){

     if(possible_new_epoch <= local_current_epoch){
         return;
     }else if(possible_new_epoch == local_current_epoch + 1){
        
        delete uidBF[0];
        uidBF[0] = uidBF[1];
        uidBF[1] = uidBF[2];        
        uidBF[2] = new BloomFilter(BF_size, BF_k, possible_new_epoch + 1); 

        delete deltaBF[0];
        deltaBF[0] = deltaBF[1];
        deltaBF[1] = deltaBF[2];        
        deltaBF[2] = new BloomFilter(BF_size, BF_k, possible_new_epoch + 1);         
     
     }else if(possible_new_epoch == local_current_epoch + 2){
        
        delete uidBF[0];
        delete uidBF[1];
        uidBF[0] = uidBF[2];
        uidBF[1] = new BloomFilter(BF_size, BF_k, possible_new_epoch); 
        uidBF[2] = new BloomFilter(BF_size, BF_k, possible_new_epoch + 1); 

        delete deltaBF[0];
        delete deltaBF[1];
        deltaBF[0] = deltaBF[2];
        deltaBF[1] = new BloomFilter(BF_size, BF_k, possible_new_epoch); 
        deltaBF[2] = new BloomFilter(BF_size, BF_k, possible_new_epoch + 1); 


     }else{

        delete uidBF[0];
        delete uidBF[1];
        delete uidBF[2];
        uidBF[0] = new BloomFilter(BF_size, BF_k, possible_new_epoch - 1); 
        uidBF[1] = new BloomFilter(BF_size, BF_k, possible_new_epoch); 
        uidBF[2] = new BloomFilter(BF_size, BF_k, possible_new_epoch + 1); 

        delete deltaBF[0];
        delete deltaBF[1];
        delete deltaBF[2];
        deltaBF[0] = new BloomFilter(BF_size, BF_k, possible_new_epoch - 1); 
        deltaBF[1] = new BloomFilter(BF_size, BF_k, possible_new_epoch); 
        deltaBF[2] = new BloomFilter(BF_size, BF_k, possible_new_epoch + 1);         

     }

    local_current_epoch = possible_new_epoch;

    //cout << "\n uidBF[0] epoch: " << uidBF[0]->my_epoch;
    //cout << "\n uidBF[1] epoch: " << uidBF[1]->my_epoch;
    //cout << "\n uidBF[2] epoch: " << uidBF[2]->my_epoch;

 }


bool Revocation::verify_revoked_slot(unsigned char* sig, long epoch)
{

        if(epoch != deltaBF[1]->my_epoch){ //se quiser tolerar alguma margem de erro, por aqui
            //cout "\nERROR in verify_revoked_slot, different epoch my_epoch: " << deltaBF[1]->my_epoch << " epoch: "<< epoch <<"\n" ;
            return true;
        }

	    //cout << "\n res: " << deltaBF[1]->possiblyContains(sig, 65*2) <<" sig: " << sig ;

        return deltaBF[1]->possiblyContains(sig, SIG_EdDSA_SIZE);

    
}
