#!/usr/bin/env bash


./runServer.sh & 
./runClient.sh &


wait
echo ""
echo "--- Figure 7 complete ---"

