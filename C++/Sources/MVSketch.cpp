#include "../Headers/MVSketch.h"
#include "../Headers/MurmurHash3.h"
#include <stdint.h>

MVSketch::MVSketch(uint32_t M, uint32_t d, uint32_t w) {
    this->M = M;
    this->d = d;
    this->w = w;
    this->HT1 = new uint32_t[M / 2];
    this->HK1 = new KEY[M / 2];
    this->HT2 = new uint32_t[M / 2];
    this->HK2 = new KEY[M / 2];
    this->B = new Bucket*[d];
    this->hash_seeds = new uint32_t[d];
    srand((uint64_t)time(NULL));
    std::unordered_set<uint32_t> mset;
    for (int i = 0; i < d; i++) {
        this->B[i] = new Bucket[w];
    }
    memset(HT1, 0, sizeof(uint32_t) * (M/2));
    memset(HT2, 0, sizeof(uint32_t) * (M/2));
    while (mset.size() != d) {
        mset.insert(rand() % 10000);
    }
    int j = 0;
    for (auto iter = mset.begin(); iter != mset.end(); iter++, j++) {
        hash_seeds[j] = *iter;
    }
    bucket_seed1 = rand() % 10000;
    bucket_seed2 = rand() % 10000;
}

void MVSketch::update(KEY key, uint32_t seq) {
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
            for (int i = 0; i < d; i++) {
                MurmurHash3_x86_32(flow_key, 12, hash_seeds[i], &hash_value);
                hash_index = hash_value % w;
                B[i][hash_index].insert(key);
            }
        }
        return;
    }
    if (HK2[hash_index2] == key) {
        if (HT2[hash_index2] < seq) {
            HT2[hash_index2] = seq;
        } else {
            for (int i = 0; i < d; i++) {
                MurmurHash3_x86_32(flow_key, 12, hash_seeds[i], &hash_value);
                hash_index = hash_value % w;
                B[i][hash_index].insert(key);
            }
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
    //             for (int i = 0; i < d; i++) {
    //                 MurmurHash3_x86_32(flow_key, 12, hash_seeds[i], &hash_value);
    //                 hash_index = hash_value % w;
    //                 B[i][hash_index].insert(key);
    //             }
    //         }
    //     }
    // }
}

int MVSketch::estimate(KEY key) {
    uint32_t hash_index, hash_value;
    char flow_key[13] = {0};
    memcpy(flow_key, &key.src_ip, 4);
    memcpy(flow_key + 4, &key.sport, 2);
    memcpy(flow_key + 6, &key.dst_ip, 4);
    memcpy(flow_key + 10, &key.dport, 2);
    int min_o3_cnt = 0x7fffffff;
    for (int i = 0; i < d; i++) {
        MurmurHash3_x86_32(flow_key, 12, hash_seeds[i], &hash_value);
        hash_index = hash_value % w;
        if (B[i][hash_index].ID == key) {
            if ((B[i][hash_index].c + B[i][hash_index].v)/2 < min_o3_cnt) {
                min_o3_cnt = (B[i][hash_index].c + B[i][hash_index].v)/2;
            }
        } else {
            if ((B[i][hash_index].v - B[i][hash_index].c)/2 < min_o3_cnt) {
                min_o3_cnt = (B[i][hash_index].v - B[i][hash_index].c)/2;
            }
        }
    }
    return min_o3_cnt;
}

std::unordered_set<KEY, KEYHash, KEYEqual> MVSketch::get_result(uint32_t T) {
    std::unordered_set<KEY, KEYHash, KEYEqual> pred_chaos;
    for (int i = 0; i < d; ++i) {
        for (int j = 0; j < w; j++) {
             if (B[i][j].v >= T) {
                 if (this->estimate(B[i][j].ID) >= T) {
                     pred_chaos.insert(B[i][j].ID);
                 }
             }   
        }
    }
    return pred_chaos;
}
