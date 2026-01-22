## O3-sketch

### Introduction

Finding chaotic flows with high out-of-order packets is critical for diagnosing performance issues in modern networks. 
Existing methods either fail to capture packet arrival order or can only handle short-term packet reordering, limiting their accuracy and generality in chaotic flow detection.
To address these challenges, we propose O3-sketch, a novel algorithm that exploits the intrinsic out-of-order behavior of network flows. Our key insight is that chaotic flows exhibit stable and persistent reordering over time, while most flows either carry a few out-of-order packets or experience transient disorder.
O3-sketch incorporates two novel metrics: out-of-order count and in-order gap count into its update strategy.
This allows it to efficiently evict normal and transient disordering flows while retaining true chaotic flows with high accuracy, even under extreme memory constraints (e.g., 32KB).
We provide rigorous theoretical guarantees for the O3-sketch and implement it on both CPU and P4 platforms.
Extensive experiments on real-world traffic traces show that O3-sketch improves F1 score by up to 2.487$\times$, reduces measurement error by at least 90\%, and improves processing speed by up to 26.167$\times$ compared to the state-of-the-art.

### About this repo

The core **O3-sketch** structure is implemented in **./C++**.

Other baseline methods are also implemented in **./C++**.

We also provide a P4-16 implementation of O3-sketch for deployment on both software and hardware programmable network switches (e.g., BMv2 switch and Tofino switch) in **./P4/BMv2/** and **./P4/Tofino/**.

### Requirements

- g++ (gcc-version >= 13.1.0)

### How to build

Before run those codes, you need to download the datasets from https://catalog.caida.org/details/dataset/passive_2019_pcap , then move them to ./data .

We preprocessed the datasets to remove all IPv6 packets to ensure that each packet contains a source IP address, a destination IP address, a source port, a destination port, and a sequence number.

You can use the following commands to build and run.

```
cd ./C++
cmake .
cmake --build . --config Release
```
