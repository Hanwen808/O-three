#include "../Headers/Lean.h"
#include "../Headers/MurmurHash3.h"
#include <stdint.h>

Lean::Lean(uint32_t _m1, uint32_t _m2) {
    this->m1 = _m1;
    this->m2 = _m2;
    HK1 = new KEY[this->m1 / 2];
    HK2 = new KEY[this->m1 / 2];
    HT1 = new unsigned[m1 / 2];
    HT2 = new unsigned[m1 / 2];
    ID2 = new KEY[this->m2];
    Count = new int[m2];
    // memset(ID1, 0, sizeof(uint64_t) * m1);
    // memset(ID2, 0, sizeof(uint64_t) * m2);
    memset(HT1, 0, sizeof(uint32_t) * (m1/2));
    memset(HT2, 0, sizeof(uint32_t) * (m1/2));
    memset(Count, 0, 4 * m2);
    srand((uint64_t)time(NULL));
    bucket_seed1 = rand() % 10000;
    bucket_seed2 = rand() % 10000;
}

void Lean::update(KEY key, uint32_t seq) {
    uint32_t hash_index1, hash_value1;
    uint32_t hash_index2, hash_value2;
    char flow_key[13] = {0};
    memcpy(flow_key, &key.src_ip, 4);
    memcpy(flow_key + 4, &key.sport, 2);
    memcpy(flow_key + 6, &key.dst_ip, 4);
    memcpy(flow_key + 10, &key.dport, 2);
    MurmurHash3_x86_32(flow_key, 12, bucket_seed1, &hash_value1);
    hash_index1 = hash_value1 % (m1/2);
    MurmurHash3_x86_32(flow_key, 12, bucket_seed2, &hash_value2);
    hash_index2 = hash_value2 % (m1/2);
    if (HK1[hash_index1] == key) {
        if (HT1[hash_index1] < seq) {
            HT1[hash_index1] = seq;
        } else {
            int empty_index = -1;
            for (int i = 0; i < m2; ++i) {
                if (ID2[i] == key) {
                    Count[i] += 1;
                    return;
                }
                if (ID2[i].is_empty())
                    empty_index = i;
            }
            if (empty_index != -1) {
                ID2[empty_index] = key;
                Count[empty_index] = 1;
            } else {
                int empty_idx2 = -1;
                for (int i = 0; i < m2; ++i) {
                    Count[i] = MAX(Count[i]-1,0);
                    if (Count[i] == 0) {
                        empty_idx2 = i;
                        ID2[i].src_ip = 0;
                        ID2[i].sport = 0;
                        ID2[i].dst_ip = 0;
                        ID2[i].dport = 0;
                    }
                }
                if (empty_idx2 != -1) {
                    ID2[empty_idx2] = key;
                    Count[empty_idx2] = 1;
                }
            }
        }
        return;
    }
    if (HK2[hash_index2] == key) {
        if (HT2[hash_index2] < seq) {
            HT2[hash_index2] = seq;
        } else {
            int empty_index = -1;
            for (int i = 0; i < m2; ++i) {
                if (ID2[i] == key) {
                    Count[i] += 1;
                    return;
                }
                if (ID2[i].is_empty())
                    empty_index = i;
            }
            if (empty_index != -1) {
                ID2[empty_index] = key;
                Count[empty_index] = 1;
            } else {
                int empty_idx2 = -1;
                for (int i = 0; i < m2; ++i) {
                    Count[i] = MAX(Count[i]-1,0);
                    if (Count[i] == 0) {
                        empty_idx2 = i;
                        ID2[i].src_ip = 0;
                        ID2[i].sport = 0;
                        ID2[i].dst_ip = 0;
                        ID2[i].dport = 0;
                    }
                }
                if (empty_idx2 != -1) {
                    ID2[empty_idx2] = key;
                    Count[empty_idx2] = 1;
                }
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
            cursor_index = tmp_hash_value % (m1/2);
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
            cursor_index = tmp_hash_value % (m1/2);
        }
    }
    // MurmurHash3_x86_32(flow_key, 12, hash_seed, &hash_value);
    // hash_index = hash_value % m1;
    // bool go_to_next = false;
    // if (ID1[hash_index].is_empty()) {
    //     ID1[hash_index] = key;
    //     Seqs[hash_index] = seq;
    // } else {
    //     if (ID1[hash_index] == key) {
    //         if (Seqs[hash_index] < seq)
    //             Seqs[hash_index] = seq;
    //         else
    //             go_to_next = true;
    //     }
    // }
    // if (go_to_next) {
    //     int empty_index = -1;
    //     for (int i = 0; i < m2; ++i) {
    //         if (ID2[i] == key) {
    //             Count[i] += 1;
    //             return;
    //         }
    //         if (ID2[i].is_empty())
    //             empty_index = i;
    //     }
    //     if (empty_index != -1) {
    //         ID2[empty_index] = key;
    //         Count[empty_index] = 1;
    //     } else {
    //         int empty_idx2 = -1;
    //         for (int i = 0; i < m2; ++i) {
    //             Count[i] = MAX(Count[i]-1,0);
    //             if (Count[i] == 0) {
    //                 empty_idx2 = i;
    //                 ID2[i].src_ip = 0;
    //                 ID2[i].sport = 0;
    //                 ID2[i].dst_ip = 0;
    //                 ID2[i].dport = 0;
    //             }
    //         }
    //         if (empty_idx2 != -1) {
    //             ID2[empty_idx2] = key;
    //             Count[empty_idx2] = 1;
    //         }
    //     }
    // }
}

int Lean::estimate(KEY key) {
    for (int i = 0; i < m2; ++i) {
        if (ID2[i] == key)
            return Count[i];
    }
    return 1;
}

std::unordered_set<KEY, KEYHash, KEYEqual> Lean::get_result(uint32_t T) {
    std::unordered_set<KEY, KEYHash, KEYEqual> pred_chaos;
    for (int i = 0; i < m2; ++i) {
        if (this->estimate(ID2[i]) >= T)
            pred_chaos.insert(ID2[i]);
    }
    return pred_chaos;
}
