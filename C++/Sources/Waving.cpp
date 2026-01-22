#include "../Headers/Waving.h"
#include <stdint.h>

WavingSketch::WavingSketch(uint32_t M, uint32_t m) {
    this->M = M;
    this->m = m;
    this->HT1 = new uint32_t[M/2];
    this->HK1 = new KEY[M/2];
    this->HT2 = new uint32_t[M/2];
    this->HK2 = new KEY[M/2];
    this->B = new Bucket[m];
    srand((uint64_t)time(NULL));
    memset(HT1, 0, sizeof(uint32_t) * (M/2));
    memset(HT2, 0, sizeof(uint32_t) * (M/2));
    bucket_seed1 = rand() % 10000;
    bucket_seed2 = rand() % 10000;
    hash_seed = rand() % 1000;
}

void WavingSketch::update(KEY key, uint32_t seq) {
    uint32_t hash_index1, hash_value1;
    uint32_t hash_index2, hash_value2;
    uint32_t hash_index, hash_value;
    char flow_key[13] = {0};
    memcpy(flow_key, &key.src_ip, 4);
    memcpy(flow_key + 4, &key.sport, 2);
    memcpy(flow_key + 6, &key.dst_ip, 4);
    memcpy(flow_key + 10, &key.dport, 2);
    MurmurHash3_x86_32(flow_key, 12, bucket_seed1, &hash_value1);
    hash_index1 = hash_value1 % (M/2);
    MurmurHash3_x86_32(flow_key, 12, bucket_seed2, &hash_value2);
    hash_index2 = hash_value2 % (M/2);
    if (HK1[hash_index1] == key) {
        if (HT1[hash_index1] < seq) {
            HT1[hash_index1] = seq;
        } else {
            MurmurHash3_x86_32(flow_key, 12, hash_seed, &hash_value);
            hash_index = hash_value % m;
            B[hash_index].insert(key);
        }
        return;
    }
    if (HK2[hash_index2] == key) {
        if (HT2[hash_index2] < seq) {
            HT2[hash_index2] = seq;
        } else {
            MurmurHash3_x86_32(flow_key, 12, hash_seed, &hash_value);
            hash_index = hash_value % m;
            B[hash_index].insert(key);
        }
        return;
    }
    if (HK1[hash_index1].is_empty()) {
        HT1[hash_index1] = seq;
        HK1[hash_index1] = key;
        return;
    }
    if (HK2[hash_index2].is_empty()) {
        HT2[hash_index2] = seq;
        HK2[hash_index2] = key;
        return;
    }
    KEY cursor_key = key;
    uint32_t cursor_seq = seq;
    int cursor_no = 1, cursor_index = hash_index1;
    for (int iii = 0; iii < TRICK; iii++) {
        if (cursor_no == 1) {
            KEY tmp_key = HK1[cursor_index];
            uint32_t tmp_seq = HT1[cursor_index];
            HK1[cursor_index] = cursor_key;
            HT1[cursor_index] = cursor_seq;
            cursor_key = tmp_key;
            cursor_seq = tmp_seq;
            cursor_no = 2;
            uint32_t tmp_hash_value;
            char evict_flow_key[13];
            memcpy(evict_flow_key, &cursor_key.src_ip, 4);
            memcpy(evict_flow_key + 4, &cursor_key.sport, 2);
            memcpy(evict_flow_key + 6, &cursor_key.dst_ip, 4);
            memcpy(evict_flow_key + 10, &cursor_key.dport, 2);
            MurmurHash3_x86_32(evict_flow_key, 12, bucket_seed2, &tmp_hash_value);
            cursor_index = tmp_hash_value % (M/2);
        } else {
            KEY tmp_key = HK2[cursor_index];
            uint32_t tmp_seq = HT2[cursor_index];
            HK2[cursor_index] = cursor_key;
            HT2[cursor_index] = cursor_seq;
            cursor_key = tmp_key;
            cursor_seq = tmp_seq;
            cursor_no = 1;
            uint32_t tmp_hash_value;
            char evict_flow_key[13];
            memcpy(evict_flow_key, &cursor_key.src_ip, 4);
            memcpy(evict_flow_key + 4, &cursor_key.sport, 2);
            memcpy(evict_flow_key + 6, &cursor_key.dst_ip, 4);
            memcpy(evict_flow_key + 10, &cursor_key.dport, 2);
            MurmurHash3_x86_32(evict_flow_key, 12, bucket_seed1, &tmp_hash_value);
            cursor_index = tmp_hash_value % (M/2);
        }
    }
    
    // MurmurHash3_x86_32(flow_key, 12, bucket_seed, &hash_value);
    // hash_index = hash_value % M;
    // if (HK[hash_index].is_empty()) {
    //     HT[hash_index] = seq;
    //     HK[hash_index] = key;
    // } else {
    //     if (HK[hash_index] == key) {
    //         if (HT[hash_index] < seq) {
    //             HT[hash_index] = seq;
    //         } else {
    //             MurmurHash3_x86_32(flow_key, 12, hash_seed, &hash_value);
    //             hash_index = hash_value % m;
    //             B[hash_index].insert(key);
    //         }
    //     }
    // }
}

int WavingSketch::estimate(KEY key) {
    uint32_t hash_index, hash_value;
    char flow_key[13] = {0};
    memcpy(flow_key, &key.src_ip, 4);
    memcpy(flow_key + 4, &key.sport, 2);
    memcpy(flow_key + 6, &key.dst_ip, 4);
    memcpy(flow_key + 10, &key.dport, 2);
    MurmurHash3_x86_32(flow_key, 12, hash_seed, &hash_value);
    hash_index = hash_value % m;
    for (int i = 0; i < D; i++) {
        if (B[hash_index].ID[i] == key && B[hash_index].flag[i] == true) {
            return B[hash_index].freq[i];
        }
    }
    int s;
    MurmurHash3_x86_32(flow_key, 12, status, &hash_value);
    if (hash_value % 2 == 0) {
        s = 1;
    } else {
        s = -1;
    }
    return B[hash_index].wc * s;   
}

std::unordered_set<KEY, KEYHash, KEYEqual> WavingSketch::get_result(uint32_t T) {
    std::unordered_set<KEY, KEYHash, KEYEqual> pred_chaos;
    for (int i = 0; i < m; ++i) {
        for (int j = 0; j < D; j++) {
            if (this->estimate(B[i].ID[j]) >= 1.0 * T) {
                pred_chaos.insert(B[i].ID[j]);
            }
        }
    }
    return pred_chaos;
}
