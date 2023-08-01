#!/usr/bin/env bash

source /opt/intel/sgxsdk/environment

make clean
make SGX_MODE=SIM
./TestApp


