#!/usr/bin/env bash

if [ "$(uname)" == "Darwin" ]; then
    # Do something under Mac OS X platform
	rm server; g++ -std=c++11 server.cpp  include/*.cpp -I include/ -lpthread -lssl -lcrypto -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -o server; ./server

elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Do something under GNU/Linux platform
 	rm server;  g++ -std=c++11 server.cpp include/*.cpp -I include/ -lssl -lcrypto -lpthread     -o server; ./server
fi



