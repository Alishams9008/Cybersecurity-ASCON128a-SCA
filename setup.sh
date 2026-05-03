#!/bin/bash
sudo apt update && sudo apt install -y gcc-arm-none-eabi binutils-arm-none-eabi
pip install numpy scipy matplotlib h5py tqdm tensorflow-cpu lief unicorn rainbow-hw 
echo "All dependencies ready."
