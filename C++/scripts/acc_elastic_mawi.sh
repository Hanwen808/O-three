#!/bin/bash

# options
optimize_flag="-O3"

compile
echo "Compiling Lean with $optimize_flag optimization flag..."
g++ ../Sources/MurmurHash3.cpp ../Sources/Elastic.cpp ../Exp/Elastic_res_mawi.cpp -o elastic_mawi -std=c++17 -I ./C++ $optimize_flag

if [ $? -eq 0 ]; then
    echo "Compilation successful. Running o3skt..."
    ./elastic_mawi
else
    echo "Compilation failed. Exiting."
    exit 1
fi
wait
rm -rf ./elastic_mawi