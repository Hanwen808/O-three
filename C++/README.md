# C++ implementation

This is a C++ implementation for O3-sketch and related solutions.

## Project Structure

```
├── ./Exp/
│   ├── Elastic_res_caida.cpp # Main function for testing ElasticSketch on CAIDA-19
│   ├── Elastic_res_mawi.cpp  # Main function for testing ElasticSketch on MAWI-24
│   ├── Lean_res.cpp          # Main function for testing Lean on CAIDA-19
│   ├── Lean_res_mawi.cpp     # Main function for testing Lean on MAWI-24
│   ├── MVsetch_res_caida.cpp # Main function for testing MVSketch on CAIDA-19
│   ├── MVsketch_res_mawi.cpp # Main function for testing MVSketch on MAWI-24
│   ├── Waving_res_caida.cpp  # Main function for testing WavingSketch on CAIDA-19
│   ├── Waving_res_mawi.cpp   # Main function for testing WavingSketch on MAWI-24
│   ├── O3Skt2_caida_d.cpp    # Parameter analysis (d) of O3-sketch on CAIDA-19
│   ├── O3Skt2_main_phi.cpp   # Parameter analysis (phi) of O3-sketch on CAIDA-19
│   ├── O3Skt2_mawi_d.cpp     # Parameter analysis (d) of O3-sketch on MAWI-24
│   ├── O3Skt2_mawi_phi.cpp   # Parameter analysis (phi) of O3-sketch on MAWI-24
│   ├── O3Skt2_res_caida.cpp  # Main function for testing O3-sketch on CAIDA-19
│   ├── O3Skt2_res_mawi.cpp   # Main function for testing O3-sketch on MAWI-24
├── ./Headers/
│   ├── MurmurHash3.h
│   ├── Elastic.h
│   ├── Lean.h
│   ├── MVSketch.h
│   ├── O3Skt2.h
│   ├── Sketch.h
│   └── Waving.h
├── ./Sources/
│   ├── Elastic.cpp
│   ├── Lean.cpp
│   ├── MurmurHash3.cpp
│   ├── MVSketch.cpp
│   ├── O3Skt2.cpp
│   └── Waving.cpp
├── ./scripts/
│   ├── acc_elastic_caida.sh
│   ├── acc_elastic_mawi.sh
│   ├── acc_lean.sh
│   ├── acc_lean_mawi.sh
│   ├── acc_mvsketch_caida.sh
│   ├── acc_mvsketch_mawi.sh
│   ├── acc_o3skt2_caida.sh
│   ├── acc_o3skt2_mawi.sh
│   ├── acc_waving_caida.sh
│   ├── acc_waving_mawi.sh
│   ├── d_o3skt2_caida.sh
│   ├── d_o3skt2_mawi.sh
│   ├── phi_o3skt2_caida.sh
│   └── phi_o3skt2_mawi.sh
```

## Usage

### Compilation
Before compiling, make sure you are in the directory /C++/. And create the following directories to save the running results of different algorithms.
```bash
$ mkdir ./Elastic_CAIDA/
$ mkdir ./Elastic_MAWI/
$ mkdir ./Lean_CAIDA/
$ mkdir ./Lean_MAWI/
$ mkdir ./MVSketch_CAIDA/
$ mkdir ./MVSketch_MAWI/
$ mkdir ./Waving_CAIDA/
$ mkdir ./Waving_MAWI/
$ mkdir ./O3Skt2_CAIDA/
$ mkdir ./O3Skt2_MAWI/
$ mkdir -p ./Params/d_caida/
$ mkdir -p ./Params/d_mawi/
$ mkdir -p ./Params/2phi_caida/
$ mkdir -p ./Params/2phi_mawi/
```

All algorithms are compiled using g++, the followding commands should be execueted.
Note that, the xxx.sh is a bash shell file including g++ compile codes with optimize_flag $-O3$.
```shell
$ chmod u+x ./scripts/acc_o3skt2_caida.sh
$ ./scripts/acc_o3skt2_caida.sh  # O3-sketch
```

## Requirements
- g++ 7.5.0 or above
- Compiler with support for C++17 standard
