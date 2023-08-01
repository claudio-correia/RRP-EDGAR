#!/usr/bin/env bash




# first

cd intel-sgx-ssl-lin_2.14_1.1.1k/Linux/sgx/performance_test/ssl-sgx/ 
./runServer_SimulatedSGX.sh &
cd ../../../../../ 


cd Client/
./runClientFig9.sh &
cd ../




wait
echo ""
echo "--- Figure 9 complete ---"
