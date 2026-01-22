#include "../Headers/O3Skt2.h"
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <random>
#include <climits>
#include <cstdlib> 
#include <iostream>
#include <cmath>
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#include "../Headers/MurmurHash3.h"

O3Skt2::O3Skt2(uint32_t _d, uint32_t _m1, uint32_t phi = 16) {
    this->d = _d;
    this->m1 = _m1;
    this->phi = phi;
    this->hash_seeds = new unsigned[this->d + 1];
    srand((uint64_t) time(NULL));
    std::unordered_set<uint32_t> mset;
    while (mset.size() != this->d + 1) {
        mset.insert(rand() % 10000);
    }
    int temp_index = 0;
    for (auto iter = mset.begin(); iter != mset.end(); iter ++) {
        hash_seeds[temp_index ++] = *iter;
    }
    this->Count1 = new unsigned *[this->d];
    this->Count2 = new unsigned *[this->d];
    this->ID1 = new KEY *[this->d];
    this->MaxSeq1 = new unsigned *[this->d];
    for (int i = 0; i < d; ++i) {
        Count1[i] = new unsigned[this->m1]{0};
        Count2[i] = new unsigned[this->m1]{0};
        ID1[i] = new KEY[this->m1];
        MaxSeq1[i] = new unsigned[this->m1]{0};
    }
}

void O3Skt2::update(KEY key, uint32_t seq) {
    alignas(16) uint8_t hash_input[12];
    memcpy(hash_input, &key.src_ip, 4);
    memcpy(hash_input + 4, &key.sport, 2);
    memcpy(hash_input + 6, &key.dst_ip, 4);
    memcpy(hash_input + 10, &key.dport, 2);
    int min_row = -1, min_col = -1;
    uint32_t min_val = UINT32_MAX;
    #pragma GCC unroll 4
    for (int i = 0; i < d; ++i) {
        uint32_t hash_value;
        MurmurHash3_x86_32(hash_input, 12, hash_seeds[i], &hash_value);
        uint32_t idx = hash_value % m1;
        
        auto& bucket_id = ID1[i][idx];
        auto& bucket_count1 = Count1[i][idx];
        auto& bucket_count2 = Count2[i][idx];
        auto& bucket_seq = MaxSeq1[i][idx];
        if (bucket_id.is_empty()) {
            bucket_id = key;
            bucket_seq = seq;
            bucket_count1 = 1;
            return;
        }
        if (bucket_id == key) {
            if (bucket_seq < seq) {
                bucket_seq = seq;
                bucket_count2 = bucket_count2 < 255 ? bucket_count2 + 1 : 256;
            } else {
                bucket_count1 = std::min(bucket_count1+1,(uint32_t)65535);
                bucket_count2 = 0;
            }
            return;
        }
        if (bucket_count1 < min_val) {
            min_row = i;
            min_col = idx;
            min_val = bucket_count1;
        }
    }
    static thread_local std::minstd_rand fast_rng(std::random_device{}());
    uint32_t rand_val = fast_rng() % 1000;
    auto& target_count1 = Count1[min_row][min_col];
    auto& target_count2 = Count2[min_row][min_col];
    
    bool should_replace = false;
    
    if (target_count1 >= phi) {
        uint32_t diff = target_count1 - target_count2;
        if (diff == 0) diff = 1;
        should_replace = (rand_val * diff < 1000);
    } else {
        should_replace = (rand_val * (1 + target_count1) < 1000);
    }
    
    if (should_replace) {
        ID1[min_row][min_col] = key;
        MaxSeq1[min_row][min_col] = seq;
        Count1[min_row][min_col] = 0;
        Count2[min_row][min_col] = 0;
    }
}

int O3Skt2::estimate(KEY key) {
    uint32_t hash_index, hash_value;
    char hash_input_str[13] = {0};
    memcpy(hash_input_str, &key.src_ip, 4);
    memcpy(hash_input_str + 4, &key.sport, 2);
    memcpy(hash_input_str + 6, &key.dst_ip, 4);
    memcpy(hash_input_str + 10, &key.dport, 2);
    for (int i = 0; i < d; ++i) {
        MurmurHash3_x86_32(hash_input_str, 12, hash_seeds[i], &hash_value);
        hash_index = hash_value % m1;
        if (ID1[i][hash_index] == key)
            return Count1[i][hash_index];
    }
    return 1;
}

std::unordered_set<KEY, KEYHash, KEYEqual> O3Skt2::get_result(uint32_t tt) {
    std::unordered_set<KEY, KEYHash, KEYEqual> pred_chaos;
    for (int i = 0; i < d; ++i) {
        for (int j = 0; j < m1; ++j) {
            if (this->estimate(ID1[i][j]) >= tt)
                pred_chaos.insert(ID1[i][j]);
        }
    }
    return pred_chaos;
}
