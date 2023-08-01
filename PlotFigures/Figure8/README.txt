Para gerar estes pontos é preciso un server, numa maquina com SGX, o cliente tem que ser noutra maquina, sem SGX.



Primeiro deve se lançar o server e depois o cliente:

Entrar na pasta:
/intel-sgx-ssl-lin_2.14_1.1.1k/Linux/sgx/performance_test/ssl-sgx/

Depois correr o server com SGX, e com as Mitigation enabled:
$ ./runServer


Pode ser preciso modificar o IP dentro do /Server/client.cpp. O server vai gerar os pontos para dentro da pasta Figures/IS_get_pseudonyms/Data/ 

Depois correr o cliente dentro da pasta  /Server
$ ./runClient
