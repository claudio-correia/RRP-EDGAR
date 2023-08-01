
# RRP/EDGAR Implementation (CCS 2023)

This is the official GitHub repository for the paper "Using Range-Revocable Pseudonyms to Provide Backward Unlinkability in the Edge," presented at CCS '23. The repository contains our code implementation and instructions on how to run the experiments. 

We offer three different ways to run our experiments. Please note that simulations (Docker and VM) are easy to run but only provide approximate results. On the other hand, executing the experiments on real hardware is more complex to deploy but offers results that are closer to the ones presented in the paper.

## Execution simulated in Docker

[Add explanation here if necessary]

## Execution simulated in VM

In this section, we explain how to run our experiments in a simulated environment within a virtual machine. We provide a VM with all the necessary installations, running Ubuntu 22.04.2 LTS, and containing the Intel SGX SDK to execute the enclave in simulation mode, OpenSSL 3, and Python3 to generate the figures. To reproduce the numbers from the paper, follow these steps:

1. Download the virtual machine from the following link:
   [https://drive.google.com/drive/folders/1tuoyePArkWoYJRObHvYIbZG6Ouvr3BYD?usp=sharing]

2. Unzip and mount the VM using VMware Workstation, which is available for Windows at:
   [https://www.vmware.com/products/workstation-player.html]
   
   or VMware Fusion for macOS at:
   [https://www.vmware.com/products/fusion.html]

4. Login (no password required) to Ubuntu inside the VM. Our code is already shipped inside the VM, so you can either open a terminal and navigate to the following directory:
   ```bash
   cd ~/Desktop/RRP-EDGAR
   ```
   <ins>or</ins> download the code from our repository into any directory inside the VM:
   ```bash
   git clone https://github.com/claudio-correia/RRP-EDGAR
   ```

5. We provide a bash script named `runFigures.sh` to automate simulations. Use the following command to run all simulations inside the root directory of our repository `RRP-EDGAR` (this simulation can take several hours, around 5 hours):
   ```bash
   ./runFigures.sh 
   ```
   The results will be stored in the `data` directory for each figure. For example, the data points for figure 7 will be stored in the `PlotFigures/Figure7/Data` directory.

6. We provide a Python script named `plotFigures.sh` to analyze results and generate figures from it.
   ```bash
   ./plotFigures.sh 
   ```
   The figures (in PDF format) will be stored in each figure's directory. For example, figure 7 is located in `PlotFigures/Figure7/figure7.pdf`.

## Execution in SGX hardware

[Add explanation here if necessary]
