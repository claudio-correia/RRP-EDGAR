
Esta pasta contem o codigo que gera os pontos nessecarios para criar a Figura 8. Este codigo depende do Intel SGX enclave, e por isso existem duas maneiras de correr o codigo: 1) Modo simulado, onde o enclave é simulado pela SDK do SGX. 2) Modo real usando o enclave em hardware.

O Codigo está preparado para correr em qualquer modo, no entanto dentro da VM apenas o codigo simulado funciona. Os pontos gerados vao ser colucados em "RRP_EDGAR/PlotFigures/Figure8" .

De seguida explicamos como correr os dois modos.


******** Modo Simulacao *********
Abrir dois terminais, na directoria de topo do projecto, "RRP_EDGAR", numa vai correr o server e noutra o cliente.

Na primeira linha de comandos fazer:
	cd CodeFigure8/intel-sgx-ssl-lin_2.14_1.1.1k/Linux/sgx/test_performance
	
Depois:

	./runServer_SimulatedSGX


No segunda terminal fazer:
	cd RRP_EDGAR/CodeFigure8
	
De seguida:
	./runClient
	
A experiencia deve estar a correr e vai terminar quando todos os pontos forem gerados e copiados para a pasta PlotFigures/Figure8 . Nessa pasta encontra se o codigo python para gerar a figura do paper.

******** Modo Hardware *********
Testado em intel5-NUC10i7FNK -> Ubuntu 22.04.2 LTS (e nem tive que fazer nada no SSL)

Para correr este modo é preciso colucar o codigo do projecto numa maquina que tenha Intel SGX disponivel no CPU e que esteja enable na BIOS, a maquina tem que estar a correr Ubunto. Para alem disto é nessesario instalar o PSW e SDK, as instrucoes encontram disponiveis aqui : https://github.com/intel/linux-sgx.


Tenho de reescrever isto, pq para ter os números bem, preciso de correr o servidor sem SGX e sem as cenas do SGX. Para isso tenho um server em c++ que faz isso. Mas server tem de correr o OpenSSL versão 1.1d se nao os números nao batem certo. 
	Tenho de entrar no compile_openssl e fazer ./Configure linux-x86_64 
	Depois fiz, mas nao sei se preciso: make e make install 
		houve um erro: dei google nao me lembro qual
	depois a correr tbm falahava tive que fazer isto (https://stackoverflow.com/questions/72133316/libssl-so-1-1-cannot-open-shared-object-file-no-such-file-or-directory) 
	wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb

	sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb

	E depois funcionou, o cliente tbm tem que ser diferente..... Para fazer so teste a fora do ecnclave.



Depois de ter os enclaves a funcionar na maquina, pode ser nessesario compilar e instalar o OpenSSL especifico para o SGX, instrucoes encontram aqui: https://github.com/intel/intel-sgx-ssl 
O projecto ja se econtra com uma versao compilada para o Ubunto, por isso este passo pode ser desnessesario.

Se tudo a cima estar correctamente configurado é possivel entao abrir dois terminais, na directoria de topo do projecto, "RRP_EDGAR", numa vai correr o server e noutra o cliente.

Na primeira linha de comandos fazer:
	cd CodeFigure8/intel-sgx-ssl-lin_2.14_1.1.1k/Linux/sgx/test_performance
	
Depois:

	./runServer_SimulatedSGX


No segunda terminal fazer:
	cd RRP_EDGAR/CodeFigure8
	
De seguida:
	./runClient
	
A experiencia deve estar a correr e vai terminar quando todos os pontos forem gerados e copiados para a pasta PlotFigures/Figure8 . Nessa pasta encontra se o codigo python para gerar a figura do paper.



******** Cliente e Servidor em maquinas diferentes *********

O cliente liga se por socket ao servidor, neste momento encontra se configurado para correr somente localmente. É possivel ligar ambas as entidades em maquinas diferentes, basta escrever o IP do servidor no codigo do Cliente no ficheiro "/RRP_EDGAR/CodeFigure8/Cliente.cpp" alterando a linhas: " communication.connect_to("127.0.0.1"); " substituidno o IP de acordo com o IP onde o servidor esta a correr. Depois seguir um dos modos descritos a cima.

É preciso estar a correr em maquinas diferentes para os numeros estarem mais proximos da realidade

































