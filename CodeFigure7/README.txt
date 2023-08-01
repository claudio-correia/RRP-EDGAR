A VM precisa de ter Cores desponivel se nao o multithread nao funciona
Nesta pasta encontram se o codigo usado para correr o AC com um cliente.
Estes devem correr em terminais diferentes, eles comunicao atravez de um socket, e usam o Openssl normal do sistema.
Basta abrir dois terminais e correr em cada um a seguinte linhas:
$ ./runServer
$ ./runClient

É preciso correr primeiro o server e agruar um pouco para ele ficar a escuta. depois correr o cliente, o cliente esta programado para se ligar ao IP local, por isso tem de estar na mesma maquina. No fim o Cliente vai gerar os pontos na pasta Figures/AC_Multithread/Data/ 
