#include "../Headers/O3Skt.h"

#include <cmath>

#include "../Headers/MurmurHash3.h"

O3Skt::O3Skt(uint32_t _d, uint32_t _m1, uint32_t _m2) {
    this->d = _d;
    this->m1 = _m1;
    this->m2 = _m2;
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
    this->ID2 = new unsigned long long[this->m2];
    memset(ID2, 0, sizeof(uint64_t) * m2);
    this->Count2 = new unsigned char[this->m2];
    memset(Count2, 0, sizeof(uint8_t) * m2);
    this->MaxSeq2 = new unsigned[this->m2];
    memset(MaxSeq2, 0, sizeof(uint32_t) * m2);

    this->Count1 = new unsigned *[this->d];
    this->ID1 = new unsigned long long *[this->d];
    this->MaxSeq1 = new unsigned *[this->d];
    for (int i = 0; i < d; ++i) {
        Count1[i] = new unsigned[this->m1]{0};
        ID1[i] = new unsigned long long[this->m1]{0};
        MaxSeq1[i] = new unsigned[this->m1]{0};
    }
    /*memset(Count1, 0, sizeof(uint32_t) * d * m1);
    memset(ID1, 0, sizeof(uint64_t) * d * m1);
    memset(MaxSeq1, 0, sizeof(uint32_t) * d * m1);*/
}

void O3Skt::update(uint64_t key, uint32_t seq) {
    uint32_t hash_index, hash_value;
    char hash_input_str[9] = {0};
    memcpy(hash_input_str, &key, 8);
    int min_row = -1, min_col = -1, min_val;
    for (int i = 0; i < d; ++i) {
        MurmurHash3_x86_32(hash_input_str, 8, hash_seeds[i], &hash_value);
        hash_index = hash_value % m1;
        if (ID1[i][hash_index] == 0) {
            ID1[i][hash_index] = key;
            MaxSeq1[i][hash_index] = seq;
            return;
        } else {
            if (ID1[i][hash_index] == key) {
                if (MaxSeq1[i][hash_index] < seq) {
                    MaxSeq1[i][hash_index] = seq;
                } else {
                    Count1[i][hash_index] += 1;
                }
                return;
            } else {
                if (min_row == -1) {
                    min_row = i;
                    min_col = hash_index;
                    min_val = Count1[i][hash_index];
                } else {
                    if (Count1[i][hash_index] < min_val) {
                        min_row = i;
                        min_col = hash_index;
                        min_val = Count1[i][hash_index];
                    }
                }
            }
        }
    }
    MurmurHash3_x86_32(hash_input_str, 8, hash_seeds[d], &hash_value);
    hash_index = hash_value % m2;
    if (ID2[hash_index] == 0) {
        ID2[hash_index] = key;
        MaxSeq2[hash_index] = seq;
    } else {
        if (ID2[hash_index] == key) {
            if (seq <= MaxSeq2[hash_index]) {
                Count2[hash_index] ++;
                if (Count2[hash_index] >= TT) {
                    ID1[min_row][min_col] = ID2[hash_index];
                    Count1[min_row][min_col] = Count2[hash_index];
                    MaxSeq1[min_row][min_col] = MaxSeq2[hash_index];
                    ID2[hash_index] = 0;
                    Count2[hash_index] = 0;
                    MaxSeq2[hash_index] = 0;
                }
            } else {
                MaxSeq2[hash_index] = seq;
            }
        } else {
            if ((1.0 * (rand() % 100) / 100.0) <= (1.0 / (1.0 + 1.0 * Count2[hash_index]))) {
                ID2[hash_index] = key;
                MaxSeq2[hash_index] = seq;
                Count2[hash_index] = 0;
            }
        }
    }
}

int O3Skt::estimate(uint64_t key) {
    uint32_t hash_index, hash_value;
    char hash_input_str[9] = {0};
    memcpy(hash_input_str, &key, 8);
    for (int i = 0; i < d; ++i) {
        MurmurHash3_x86_32(hash_input_str, 8, hash_seeds[i], &hash_value);
        hash_index = hash_value % m1;
        if (ID1[i][hash_index] == key)
            return Count1[i][hash_index];
    }
    MurmurHash3_x86_32(hash_input_str, 8, hash_seeds[d], &hash_value);
    hash_index = hash_value % m2;
    if (ID2[hash_index] == key)
        return Count2[hash_index];
    else
        return 1;
}

std::unordered_set<uint64_t> O3Skt::get_result(uint32_t tt) {
    std::unordered_set<uint64_t> pred_chaos;
    for (int i = 0; i < d; ++i) {
        for (int j = 0; j < m1; ++j) {
            if (this->estimate(ID1[i][j]) >= tt)
                pred_chaos.insert(ID1[i][j]);
        }
    }
    return pred_chaos;
}
