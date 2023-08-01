#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>       // std::cout
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define PORT 8080

using namespace std;


class Communication
{    
    
    public:

    int sockfd;
    struct sockaddr_in address;
    
    int local_socket; //para quando uma thead é lacancad poder comunicar com o client

    void init();
    void init(int socket);
    void Magic_Socket(int socket);    
    void connect_to(const char* IPaddr);    
    void close_connection();
    void wait_connection();    
    int wait_request(int *current_request_type, int *current_socket);
    int read_int();
    int read_buff(unsigned char*output, size_t size );
    int msg_send(int value1);
    int msg_send(char* msg, int msgsize);    
    int msg_send(const void* msg, int msgsize);

}; 