#!/usr/bin/env bash

if [ "$(uname)" == "Darwin" ]; then
    # Do something under Mac OS X platform
	rm client; g++ -std=c++11 client.cpp  include/*.cpp -I include/ -lpthread -lssl -lcrypto -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -o client;

elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Do something under GNU/Linux platform
 	rm client;  g++ -std=c++11 client.cpp include/*.cpp -I include/ -lssl -lcrypto -lpthread -o client;
fi



while ! ./client 3
do
    sleep 1
    echo "fail, trying again"
done
