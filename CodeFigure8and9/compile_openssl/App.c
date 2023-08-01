#include <stdio.h>
#include <openssl/opensslv.h>
//#include "openssl/sha.h"

 


int main(int argc, char *argv[])
{
    printf("Hello, World!");
    printf("version: " OPENSSL_VERSION_TEXT);

    //cout << "\version : "<<  OPENSSL_VERSION_TEXT <<" \n" << endl;

    return 0;

}