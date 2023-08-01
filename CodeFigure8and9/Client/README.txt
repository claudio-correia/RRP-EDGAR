Os Bloom filters foram feitos por aqui: https://findingprotopia.org/posts/how-to-write-a-bloom-filter-cpp/
OpenSSL a funcinar no MacOs -> https://github.com/openssl/openssl/issues/4611 https://kentakodashima.medium.com/generate-pem-keys-with-openssl-on-macos-ecac55791373
OpenSSL symetric encryption aesgcm -> https://github.com/majek/openssl/blob/master/demos/evp/aesgcm.c


Nesta pasta encontram se o codigo usado para correr o Server com um cliente.
Estes devem correr em terminais diferentes, eles comunicao atravez de um socket, e usam o Openssl normal do sistema.
Basta abrir dois terminais e correr em cada um a seguinte linhas:
$ ./runServer
$ ./runClient

É preciso correr primeiro o server e agruar um pouco para ele ficar a escuta. depois correr o cliente, o cliente esta programado para se ligar ao IP remoto, dentro do client.cpp é possivel defenir o IP. No fim o Cliente vai gerar os pontos na pasta Figures/AC_Multithread/Data/ 


Para ver o porcesso que esta com o mesmo adress: netstat -tulpn

