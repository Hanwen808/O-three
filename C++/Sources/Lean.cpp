#include "../Headers/Lean.h"
#include "../Headers/MurmurHash3.h"

Lean::Lean(uint32_t _m1, uint32_t _m2) {
    this->m1 = _m1;
    this->m2 = _m2;
    ID1 = new unsigned long long[this->m1];
    Seqs = new unsigned[m1];
    ID2 = new unsigned long long[this->m2];
    Count = new int[m2];
    memset(ID1, 0, sizeof(uint64_t) * m1);
    memset(ID2, 0, sizeof(uint64_t) * m2);
    memset(Seqs, 0, sizeof(uint32_t) * m1);
    memset(Count, 0, 4 * m2);
    srand((uint64_t)time(NULL));
    hash_seed = rand() % 10000;
}

void Lean::update(uint64_t key, uint32_t seq) {
    uint32_t hash_index, hash_value;
    char flow_key[9] = {0};
    memcpy(flow_key, &key, 8);
    MurmurHash3_x86_32(flow_key, 8, hash_seed, &hash_value);
    hash_index = hash_value % m1;
    bool go_to_next = false;
    if (ID1[hash_index] == 0) {
        ID1[hash_index] = key;
        Seqs[hash_index] = seq;
    } else {
        if (ID1[hash_index] == key) {
            if (Seqs[hash_index] < seq)
                Seqs[hash_index] = seq;
            else
                go_to_next = true;
        }
    }
    if (go_to_next) {
        int empty_index = -1;
        for (int i = 0; i < m2; ++i) {
            if (ID2[i] == key) {
                Count[i] += 1;
                return;
            }
            if (ID2[i] == 0)
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
                    ID2[i] = 0;
                }
            }
            if (empty_idx2 != -1) {
                ID2[empty_idx2] = key;
                Count[empty_idx2] = 1;
            }
        }
    }
}

int Lean::estimate(uint64_t key) {
    for (int i = 0; i < m2; ++i) {
        if (ID2[i] == key)
            return Count[i];
    }
    return 1;
}

std::unordered_set<uint64_t> Lean::get_result(uint32_t T) {
    std::unordered_set<uint64_t> pred_chaos;
    for (int i = 0; i < m2; ++i) {
        if (this->estimate(ID2[i]) >= T)
            pred_chaos.insert(ID2[i]);
    }
    return pred_chaos;
}
