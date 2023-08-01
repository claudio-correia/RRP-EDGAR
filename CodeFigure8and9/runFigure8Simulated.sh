#!/usr/bin/env bash




# first

cd intel-sgx-ssl-lin_2.14_1.1.1k/Linux/sgx/performance_test/ssl-sgx/ 
./runServer_SimulatedSGX.sh &
cd ../../../../../ 


cd Client/
./runClientFig8.sh &
cd ../


wait
echo ""
echo " Fig 8 first part completed"




# second part, no sgx

cd intel-sgx-ssl-lin_2.14_1.1.1k/Linux/sgx/performance_test/ssl-sgx/ 
./runServer_SimulatedSGX.sh &
cd ../../../../../ 


cd Client/
./runClientNoSGX.sh &
cd ../





wait
echo ""
echo "--- Figure 8 complete ---"
