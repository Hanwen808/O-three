## O3-sketch

### Introduction

Finding chaotic flows with high out-of-order packets is critical for diagnosing network performance issues. However, prior solutions fail to capture fine-grained per-flow out-of-order patterns, resulting in the loss of critical sequence information and reduced accuracy in chaotic flow detection. Moreover, their reliance on strong assumptions about packet arrival order further limits their flexibility. In this paper, we propose O3-sketch to achieve fast, flexible, and memory-efficient chaotic flow detection. By jointly considering the difference between the arriving and recorded sequence numbers and the recorded out-of-order count, we design a novel probabilistic replacement strategy. This strategy ensures that chaotic flows, with either persistently high or temporarily low out-of-order counts, can be correctly tracked, while non-chaotic flows are efficiently evicted. We theoretically prove that O3-sketch has one-sided error and derive a tight probabilistic error bound. We implement O3-sketch on an Intel Tofino programmable switch to demonstrate its hardware friendliness. Extensive experiments on real-world traffic traces show that O3-sketch improves chaotic flow detection accuracy by up to 45.74\% and achieves up to 291.25\(\times\) higher throughput than the state-of-the-art.

### About this repo

The core **O3-sketch** structure is implemented in **./C++**.

Other baseline methods are also implemented in **./C++**.

### Requirements

- g++ (gcc-version >= 13.1.0)

### How to build

Before run those codes, you need to download the datasets from https://catalog.caida.org/details/dataset/passive_2019_pcap , then move them to ./data .

We preprocessed the datasets to remove all IPv6 packets to ensure that each packet contains a source IP address, a destination IP address, a source port, a destination port, and a sequence number.

You can use the following commands to build and run.

```
g++ ./tcp_CDM_4KB.cpp -o tcp_CDM_4KB -std=c++17 -mavx2 -O3
./tcp_CDM_4KB
```
