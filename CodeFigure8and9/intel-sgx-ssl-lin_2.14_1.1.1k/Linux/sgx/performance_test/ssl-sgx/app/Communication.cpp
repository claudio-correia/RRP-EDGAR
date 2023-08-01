#include "Communication.h"




void Communication::init(){
    


     int portno = 9999;
     // create a TCP/IP socket
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0)
        perror("ERROR opening socket");

     struct sockaddr_in serv_addr;
     // clear address structure
     bzero((char *) &serv_addr, sizeof(serv_addr));

     /* setup the host_addr structure for use in bind call */
     // server byte order
     serv_addr.sin_family = AF_INET;

     // automatically be filled with current host's IP address
     serv_addr.sin_addr.s_addr = INADDR_ANY;

     // port number to bind to
     serv_addr.sin_port = htons(portno);

    int yes = 1;
    int result = setsockopt(sockfd,IPPROTO_TCP,TCP_NODELAY,(char *) &yes, sizeof(int));    // 1 - on, 0 - off
    yes = 1;
    #ifdef __linux__
    setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, (char *) &yes, sizeof(int));
    #endif

    int tr=1;

    // kill "Address already in use" error message
    if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&tr,sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

     // This bind() call will bind  the socket to the current IP address on port
     if (::bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
         perror("ERROR on binding");
     }

     // This listen() call tells the socket to listen to the incoming connections.
     // The listen() function places all incoming connection into a backlog queue
     // until accept() call accepts the connection.
     // Here, we set the maximum size for the backlog queue to 5.
     listen(sockfd,500);


  
 

}


void Communication::Magic_Socket(int socket){

    int yes = 1;
    int result = setsockopt(socket,IPPROTO_TCP,TCP_NODELAY,(char *) &yes, sizeof(int));    // 1 - on, 0 - off
    
    yes = 1;
    #ifdef __linux__
    setsockopt(socket, IPPROTO_TCP, TCP_QUICKACK, (char *) &yes, sizeof(int));
    #endif

}

void Communication::connect_to(const char* IPaddr) {  


    int portno = 9999;
    struct sockaddr_in serv_addr;
    local_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (local_socket < 0)
        perror("ERROR opening socket");
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IPaddr);
    serv_addr.sin_port = htons(portno);


    Magic_Socket(local_socket);

    if (connect(local_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0) 
    {
        //printf("connected\n");

    }
    else
        perror("ERROR connecting");

}


void Communication::close_connection(){
    close(local_socket);
}



void Communication::init(int socket){
    local_socket = socket;
}



void Communication::wait_connection() {
  
    //cout << " test listening \n";


    local_socket = accept(sockfd, 0, 0);

    Magic_Socket(local_socket);


}

struct sockaddr_in svrAdd, clntAdd;

int Communication::wait_request(int *current_request_type, int *current_socket) {
  
    int valread;
    //cout << " test listening \n";


    //*current_socket = accept(sockfd, 0, 0);
    
    socklen_t len = sizeof(clntAdd); 
    *current_socket = accept(sockfd,(struct sockaddr *)&clntAdd, &len);
    //cout << " new client \n";


    Magic_Socket( *current_socket );


    valread = read(*current_socket, current_request_type, sizeof(int));
    
    return valread;

}

int Communication::msg_send(int value1) {

    int ret = write(local_socket , &value1 , sizeof(int)  );
    Magic_Socket(local_socket);


    if (ret < 0){ 
        perror("ERROR read_int");
    }


    return 0;
}

int Communication::msg_send(char* msg, int msgsize) {

    write(local_socket , msg , msgsize );
    Magic_Socket(local_socket);

    return 0;
}

int Communication::msg_send(const void* msg, size_t msgsize) {

    write(local_socket , msg , msgsize );
    Magic_Socket(local_socket);

    return 0;
}

int Communication::read_int(){
    int valread;
    int msg_received;

    valread = read( local_socket , &msg_received, sizeof(int));
    //cout << " read_int: "<< msg_received << "\n";

    if (valread < 0){ 
        perror("ERROR read_int");
    }

    Magic_Socket(local_socket);

    return msg_received;
}

int Communication::read_buff(unsigned char* output, int bytes ){

    //cout << " bytes: "<< bytes << "\n";
    
    int bytes_read = 0;
    while (bytes_read < bytes) {

        int b = read( local_socket , (output + bytes_read), (bytes - bytes_read));
        bytes_read += b;
    
    }
    Magic_Socket(local_socket);

    //cout << " bytes_read: "<< bytes_read << "\n";

    return bytes_read;
}

