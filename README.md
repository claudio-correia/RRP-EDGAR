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

[Add explanation here if necessary]