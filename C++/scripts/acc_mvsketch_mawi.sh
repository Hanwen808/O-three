#!/bin/bash

# options
optimize_flag="-O3"

compile
echo "Compiling Lean with $optimize_flag optimization flag..."
g++ ../Sources/MurmurHash3.cpp ../Sources/MVSketch.cpp ../Exp/MVsketch_res_mawi.cpp -o mvsketch_mawi -std=c++17 -I ./C++ $optimize_flag

if [ $? -eq 0 ]; then
    echo "Compilation successful. Running mvsketch..."
    ./mvsketch_mawi
else
    echo "Compilation failed. Exiting."
    exit 1
fi
wait
rm -rf ./mvsketch_mawi