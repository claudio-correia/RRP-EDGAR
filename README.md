
# RRP/EDGAR Implementation (CCS 2023)

This is the official GitHub repository for the paper "Using Range-Revocable Pseudonyms to Provide Backward Unlinkability in the Edge," presented at CCS '23. The repository contains our code implementation and instructions on how to run the experiments. 

We offer three different ways to run our experiments. Please note that simulations (Docker and VM) are easy to run but only provide approximate results. On the other hand, executing the experiments on real hardware is more complex to deploy but offers results that are closer to the ones presented in the paper.

## Execution simulated in Docker

In this section, we explain how to run our experiments in a simulated environment within a Docker container. We provide a Docker image running Ubuntu 22.04, with the Intel SGX SDK to execute the enclave in simulation mode, OpenSSL 3, and Python3 to generate the figures. To reproduce the numbers from the paper, follow these steps:

1. Download and install Docker locally, available at:
   [https://www.docker.com/]

2. Pull the pre-built Docker image from: `https://hub.docker.com/r/claudio21/rrp-edgar:1.0`
   ```bash
   docker pull claudio21/rrp-edgar:1.0
   ```

3. Create and run the container.
   ```bash
   docker create -it --name EDGAR claudio21/rrp-edgar:1.0
   docker start EDGAR
   docker attach EDGAR 
   ```

4. Our code is already available inside the container. You can either use the terminal and navigate to the following directory:
   ```bash
   cd /home/RRP-EDGAR
   ```
   <ins>or</ins> download the code from our repository into any directory inside the container:
   ```bash
   git clone https://github.com/claudio-correia/RRP-EDGAR
   ```

5. Run the simulations using the provided bash script, executing it inside the root directory of our repository `RRP-EDGAR` (this simulation can take several hours, around 5 hours):
   ```bash
   ./runFigures.sh 
   ```
   The results will be stored in the `data` directory for each figure. For example, the data points for figure 7 will be stored in the `PlotFigures/Figure7/Data` directory.

6. Analyze the results and generate figures using the provided Python script.
   ```bash
   ./plotFigures.sh 
   ```
   The figures (in PDF format) will be stored in each figure's directory. For example, figure 7 is located in `PlotFigures/Figure7/figure7.pdf`.

7. Exit the container and move the generated figures to be visualized.
   ```bash
   exit
   docker cp EDGAR:/home/RRP-EDGAR/PlotFigures/Figure7/figure7.pdf .
   docker cp EDGAR:/home/RRP-EDGAR/PlotFigures/Figure8/figure8.pdf .
   docker cp EDGAR:/home/RRP-EDGAR/PlotFigures/Figure9/figure9.pdf .
   ```

## Execution simulated in VM

In this section, we explain how to run our experiments in a simulated environment within a virtual machine. We provide a VM with all the necessary installations, running Ubuntu 22.04.2 LTS, with the Intel SGX SDK to execute the enclave in simulation mode, OpenSSL 3, and Python3 to generate the figures. To reproduce the numbers from the paper, follow these steps:

1. Download the virtual machine from the following link:
   [https://drive.google.com/drive/folders/1tuoyePArkWoYJRObHvYIbZG6Ouvr3BYD?usp=sharing]

2. Unzip and mount the VM using VMware Workstation, available for Windows at:
   [https://www.vmware.com/products/workstation-player.html]
   or VMware Fusion for macOS at:
   [https://www.vmware.com/products/fusion.html]

3. Login (no password required) to Ubuntu inside the VM. Our code is already available inside the VM. You can either open a terminal and navigate to the following directory:
   ```bash
   cd ~/Desktop/RRP-EDGAR
   ```
   <ins>or</ins> download the code from our repository into any directory inside the VM:
   ```bash
   git clone https://github.com/claudio-correia/RRP-EDGAR
   ```

4. Run the simulations using the provided bash script, executing it inside the root directory of our repository `RRP-EDGAR` (this simulation can take several hours, around 5 hours):
   ```bash
   ./runFigures.sh 
   ```
   The results will be stored in the `data` directory for each figure. For example, the data points for figure 7 will be stored in the `PlotFigures/Figure7/Data` directory.

5. Analyze the results and generate figures using the provided Python script.
   ```bash
   ./plotFigures.sh 
   ```
   The figures (in PDF format) will be stored in each figure's directory. For example, figure 7 is located in `PlotFigures/Figure7/figure7.pdf`.

## Execution in SGX hardware
In this final section, we explain how to run our experiments in a real Intel SGX hardware. This deployment is more complex but it provides more accurate results. For this deploymt is requred two machiens: 

- The **Server**:  the server machine must have Intel SGX availbel in the CPU and must be enabled in the BIOS. In our eseprriments we have used a Intel NUC10i7FNK 16GB RAM, and Ubuntu 22.04 LTS. We run the Intel SGX SDK Linux 2.13 Release version, Intel SSL-SGX, Pyhton3, Linux 2.14_1.1.1k and OpenSSL 1.1.1k. (CORRIGIR) 
- The **Client**:  the client machine does not require SGX. We have used a machine simioar to the server, but is also possoible to use the preicusl presented docker container <ins>only</ins>  for the client.


Both machines must be conneccted and reachble in a local network. The cclient needs to know the server IP, during this guuide we instruct when to provide this IP adress. 

### Intel Driver/SDK/PSW installation

The server machine needs to have the Intel Driver, SDK, and PSW installed to run enclaves on the local CPU. The installation of this package depends on the machine's hardware and operating system. Detailed instructions are provided by Intel at: [https://github.com/intel/linux-sgx].

It is recommended to follow the steps described by Intel in the above link. However, we also provide the steps we took to install these packages on our server. After installing a clean version of Ubuntu 22.04 LTS and enabling SGX in the BIOS, we followed these steps:

1.  Install required packages and dependencies:
   ```bash
   sudo apt update
   sudo apt-get upgrade
   sudo apt install build-essential
   sudo apt-get install linux-headers-$(uname -r)
   sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
   sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
   sudo apt-get install vim
   sudo apt-get install build-essential python-is-python3
   sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev 
   ```

2. We installed the Intel SGX driver, available here: [https://github.com/intel/linux-sgx-driver].
   ```bash
   cd ~/Downloads/
   git clone https://github.com/intel/linux-sgx-driver
   cd linux-sgx-driver
   make
   sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
   sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
   sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
   sudo /sbin/depmod
   sudo /sbin/modprobe isgx
   ```
3. Install the Intel SGX SDK:
   ```bash
   cd ~/Downloads/
   git clone https://github.com/intel/linux-sgx.git
   cd linux-sgx && make preparation
   sudo cp external/toolset/ubuntu20.04/* /usr/local/bin
   which ar as ld objcopy objdump ranlib 
   make sdk
   make sdk_install_pkg

   cd /opt/
   sudo mkdir intel
   cd ~/Downloads/linux-sgx/linux/installer/bin       
   ```
   When executing the following command, answer "no," and then specify that the directory is "/opt/intel/":
   ```bash
   sudo ./sgx_linux_x64_sdk_2.20.100.4.bin
   ```

4. Install the Intel SGX PSW:
   ```bash
   cd ~/Downloads/linux-sgx
   make psw
   make deb_psw_pkg
   make deb_local_repo
   ```
   Now it is necessary to add a line to the `/etc/apt/sources.list` file. To do this, we use the vim editor:
   ```bash
   sudo vim  /etc/apt/sources.list
   ```

   And we add the line:
   ```bash
   deb [trusted=yes archamd64] file:/home/intelnuc5/Downloads/linux-sgx/linux/installer/deb/sgx_debian_local_repo jammy main
   ```
   Finally, it is possible to install the PSW:
   
   ```bash
   sudo apt update
   sudo apt-get install libsgx-launch libsgx-urts
   ```

### OpenSSL installation
In our code, we use OpenSSL inside and outside the enclave, and to achieve this, we followed the instructions provided here: [https://github.com/intel/intel-sgx-ssl]. Our project includes the necessary files to use OpenSSL version 1.1d, which can be found inside the folder `/RRP-EDGAR/CodeFigure8and9/compile_openssl`.

Tenho de confimar isto......
Dentro desta pasta fiz:
./Configure linux-x86_64
 make e make install









