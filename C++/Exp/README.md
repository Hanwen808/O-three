# C++ implementation

This is a C++ implementation for O3-sketch and related solutions.

## Project Structure

```
./
├── Elastic_res_caida.cpp # Main function for testing ElasticSketch on CAIDA-19
├── Elastic_res_mawi.cpp  # Main function for testing ElasticSketch on MAWI-24
├── Lean_res.cpp          # Main function for testing Lean on CAIDA-19
├── Lean_res_mawi.cpp     # Main function for testing Lean on MAWI-24
├── MVsetch_res_caida.cpp # Main function for testing MVSketch on CAIDA-19
├── MVsketch_res_mawi.cpp # Main function for testing MVSketch on MAWI-24
├── Waving_res_caida.cpp  # Main function for testing WavingSketch on CAIDA-19
├── Waving_res_mawi.cpp   # Main function for testing WavingSketch on MAWI-24
├── O3Skt2_caida_d.cpp    # Parameter analysis (d) of O3-sketch on CAIDA-19
├── O3Skt2_main_phi.cpp   # Parameter analysis (phi) of O3-sketch on CAIDA-19
├── O3Skt2_mawi_d.cpp     # Parameter analysis (d) of O3-sketch on MAWI-24
├── O3Skt2_mawi_phi.cpp   # Parameter analysis (phi) of O3-sketch on MAWI-24
├── O3Skt2_res_caida.cpp  # Main function for testing O3-sketch on CAIDA-19
├── O3Skt2_res_mawi.cpp   # Main function for testing O3-sketch on MAWI-24
├── ../Headers/
│   ├── MurmurHash3.h
│   ├── Elastic.h
│   ├── Lean.h
│   ├── MVSketch.h
│   ├── O3Skt2.h
│   ├── Sketch.h
│   └── Waving.h
├── ../Sources/
│   ├── Elastic.cpp
│   ├── Lean.cpp
│   ├── MurmurHash3.cpp
│   ├── MVSketch.cpp
│   ├── O3Skt2.cpp
│   └── Waving.cpp
```
