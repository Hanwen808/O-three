#include "../Headers/LeanCF.h"
#include "../Headers/MurmurHash3.h"

LeanCF::LeanCF(uint32_t _m1, uint32_t _m2) {
    this->m1 = _m1;
    this->m2 = _m2;
    ID1 = new unsigned[this->m1];
    Seqs = new unsigned[m1];
    ID2 = new uint64_t[this->m2];
    Count = new int[m2];
    memset(ID1, 0, sizeof(uint32_t) * m1);
    memset(ID2, 0, sizeof(uint64_t) * m2);
    memset(Seqs, 0, sizeof(uint32_t) * m1);
    memset(Count, 0, 4 * m2);
    srand((uint64_t)time(NULL));
    hash_seed = rand() % 10000;
    hash_seed2 = rand() % 5000;
}

void LeanCF::evict(uint32_t fp, uint32_t seq, uint32_t loc) {
    if (ID1[loc] != 0) {
        uint32_t kicked_fp = ID1[loc];
        uint32_t kicked_seq = Seqs[loc];
        ID1[loc] = fp;
        Seqs[loc] = seq;
        uint32_t hash_index, hash_value;
        char flow_key[9] = {0};
        memcpy(flow_key, &kicked_fp, 4);
        MurmurHash3_x86_32(flow_key, 4, hash_seed, &hash_value);
        hash_index = (loc ^ hash_value) % m1;
        kicked_num ++;
        if (kicked_num < MAXKICK) {
            this->evict(kicked_fp, kicked_seq, hash_index);
        } else {
            kicked_num = 0;
            return;
        }
    } else {
        ID1[loc] = fp;
        Seqs[loc] = seq;
        return;
    }
}

void LeanCF::update(uint64_t key, uint32_t seq) {
    uint32_t hash_index, hash_value;
    uint32_t fp_value, fp_hash_value;
    char flow_key[9] = {0};
    memcpy(flow_key, &key, 8);
    MurmurHash3_x86_32(flow_key, 8, hash_seed, &hash_value);
    hash_index = hash_value % m1;
    MurmurHash3_x86_32(flow_key, 8, hash_seed2, &fp_value);
    bool go_to_next = false;
    if (ID1[hash_index] == 0) {
        ID1[hash_index] = fp_value;
        Seqs[hash_index] = seq;
    } else {
        if (ID1[hash_index] == fp_value) {
            if (Seqs[hash_index] < seq)
                Seqs[hash_index] = seq;
            else
                go_to_next = true;
        } else {
            uint32_t next_hash_index;
            //MurmurHash3_x86_32(flow_key, 8, hash_seed2, &hash_value);
            memset(flow_key, 0, 9);
            memcpy(flow_key, &fp_value, 4);
            MurmurHash3_x86_32(flow_key, 4, hash_seed, &fp_hash_value);
            next_hash_index = (hash_index ^ fp_hash_value) % m1;
            if (ID1[next_hash_index] == 0) {
                ID1[next_hash_index] = fp_value;
                Seqs[next_hash_index] = seq;
            } else {
                if (ID1[next_hash_index] == fp_value) {
                    if (Seqs[next_hash_index] < seq)
                        Seqs[next_hash_index] = seq;
                    else
                        go_to_next = true;
                } else {
                    uint32_t kicked_fp = ID1[next_hash_index];
                    uint32_t kicked_seq = Seqs[next_hash_index];
                    ID1[next_hash_index] = fp_value;
                    Seqs[next_hash_index] = seq;
                    kicked_num ++;
                    char kicked_flow_fp[9];
                    memcpy(kicked_flow_fp, &kicked_fp, 4);
                    MurmurHash3_x86_32(kicked_flow_fp, 4, hash_seed, &fp_hash_value);
                    hash_index = (next_hash_index ^ fp_hash_value) % m1;
                    this->evict(kicked_fp, kicked_seq, hash_index);
                }
            }
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

int LeanCF::estimate(uint64_t key) {
    for (int i = 0; i < m2; ++i) {
        if (ID2[i] == key)
            return Count[i];
    }
    return 1;
}

std::unordered_set<uint64_t> LeanCF::get_result(uint32_t T) {
    std::unordered_set<uint64_t> pred_chaos;
    for (int i = 0; i < m2; ++i) {
        if (this->estimate(ID2[i]) >= T)
            pred_chaos.insert(ID2[i]);
    }
    return pred_chaos;
}
