#ifndef ELASTIC_H
#define ELASTIC_H
#include "Sketch.h"

#define LAM 8

typedef struct tmpbucket {
    KEY ID;
    uint32_t votep = 0, voten = 0;
    bool flag = false;
    bool insert(KEY key, KEY* return_key, uint32_t* return_votep) {
        if (ID == key) {
            votep += 1;
            return true;
        } else {
            if (ID.is_empty()) {
                ID = key;
                votep += 1;
                return true;
            } else {
                voten += 1;
                if (voten / votep >= LAM) {
                    *return_key = ID;
                    *return_votep = votep;
                    ID = key;
                    votep = 1;
                    voten = 0;
                    flag = true;
                }
                return false;
            }
        }
    }
} Bucket;

class ElasticSketch : public Sketch {
private:
    KEY *HK1;
    KEY *HK2;
    uint32_t *HT1;
    uint32_t *HT2;
    Bucket *B;
    uint32_t **C;
    uint32_t bucket_seed1, bucket_seed2;
    uint32_t *hash_seeds;
    uint32_t M, m, d, w;
public:
    ElasticSketch(uint32_t, uint32_t, uint32_t, uint32_t);
    ~ElasticSketch() {
        delete[] HK1;
        delete[] HT1;
        delete[] HK2;
        delete[] HT2;
        delete[] B;
        delete[] C;
        delete[] hash_seeds;
    }
    void update(KEY, uint32_t);
    int estimate(KEY);
    std::unordered_set<KEY, KEYHash, KEYEqual> get_result(uint32_t);
};

#endif //ELASTIC_H
