#!/bin/bash

# options
optimize_flag="-O3"

compile
echo "Compiling Lean with $optimize_flag optimization flag..."
g++ ../Sources/MurmurHash3.cpp ../Sources/O3Skt2.cpp ../Exp/O3Skt2_caida_d.cpp -o d_o3skt2_caida -std=c++17 -I ./C++ $optimize_flag

if [ $? -eq 0 ]; then
    echo "Compilation successful. Running o3skt..."
    ./d_o3skt2_caida
else
    echo "Compilation failed. Exiting."
    exit 1
fi
wait
rm -rf ./d_o3skt2_caida