#ifndef WAVING_H
#define WAVING_H
#include "Sketch.h"
#include "MurmurHash3.h"
#include <iostream>
#define D 4
#define status 88123

typedef struct tmpbucket {
    int wc = 0;
    KEY ID[D];
    int freq[D];
    bool flag[D];

    tmpbucket() {
        for (int i = 0; i < D; i++) {
            freq[i] = 0;
            flag[i] = true;
        }
    }

    bool insert(KEY key) {
        //std::cout << wc << " " << freq[0] << " " << flag[0] << std::endl; 
        uint32_t hash_value;
        int s;
        char flow_key[13] = {0};
        memcpy(flow_key, &key.src_ip, 4);
        memcpy(flow_key + 4, &key.sport, 2);
        memcpy(flow_key + 6, &key.dst_ip, 4);
        memcpy(flow_key + 10, &key.dport, 2);
        MurmurHash3_x86_32(flow_key, 12, status, &hash_value);
        if (hash_value % 2 == 0) {
            s = 1;
        } else {
            s = -1;
        }
        int est_freq = s * wc;
        int empty_col = -1, min_col = -1, min_val = -1;
        for (int i = 0; i < D; i++) {
            if (ID[i] == key) {
                freq[i] += 1;
                if (flag[i] == false) {
                    wc += s;
                }
                return true;
            } else {
                if (ID[i].is_empty()) {
                    empty_col = i;
                } else {
                    if (min_col == -1) {
                        min_col = i;
                        min_val = freq[i];
                    } else {
                        if (freq[i] < min_val) {
                            min_col = i;
                            min_val = freq[i];
                        }
                    }
                }
            }
        }
        
        if (empty_col != -1) {
            ID[empty_col] = key;
            freq[empty_col] = 1;
            flag[empty_col] = true;
        } else {
            wc += s;
            if (est_freq >= freq[min_col]) {
                if (flag[min_col] == true) {
                    int r_s;
                    char flow_key[13] = {0};
                    memcpy(flow_key, &ID[min_col].src_ip, 4);
                    memcpy(flow_key + 4, &ID[min_col].sport, 2);
                    memcpy(flow_key + 6, &ID[min_col].dst_ip, 4);
                    memcpy(flow_key + 10, &ID[min_col].dport, 2);
                    MurmurHash3_x86_32(flow_key, 12, status, &hash_value);
                    if (hash_value % 2 == 0) {
                        r_s = 1;
                    } else {
                        r_s = -1;
                    }
                    wc += r_s * freq[min_col];
                }
                ID[min_col] = key;
                freq[min_col] = est_freq + 1;
                flag[min_col] = false;
            }
        }
        return true;
    }
} Bucket;

class WavingSketch : public Sketch {
private:
    KEY *HK1, *HK2;
    uint32_t *HT1, *HT2;
    Bucket *B;
    uint32_t bucket_seed1, bucket_seed2;
    uint32_t hash_seed;
    uint32_t M, m;
public:
    WavingSketch(uint32_t, uint32_t);
    ~WavingSketch() {
        delete[] HK1;
        delete[] HT1;
        delete[] HK2;
        delete[] HT2;
        delete[] B;
    }
    void update(KEY, uint32_t);
    int estimate(KEY);
    std::unordered_set<KEY, KEYHash, KEYEqual> get_result(uint32_t);
};

#endif //WAVING_H
