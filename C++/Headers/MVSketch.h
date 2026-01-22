#ifndef MVSKETCH_H
#define MVSKETCH_H
#include "Sketch.h"

#define LAM 8

typedef struct tmpbucket {
    KEY ID;
    int c = 0;
    int v = 0;
    bool insert(KEY key) {
        v += 1;
        if (ID == key) {
            c += 1;
        } else {
            c -= 1;
            if (c < 0) {
                ID = key;
                c = -c;
            }
        }
        return true;
    }
} Bucket;

class MVSketch : public Sketch {
private:
    KEY *HK1, *HK2;
    uint32_t *HT1, *HT2;
    Bucket **B;
    uint32_t *hash_seeds;
    uint32_t M, d, w, bucket_seed1, bucket_seed2;
public:
    MVSketch(uint32_t, uint32_t, uint32_t);
    ~MVSketch() {
        delete[] HK1;
        delete[] HT1;
        delete[] HK2;
        delete[] HT2;
        delete[] B;
        delete[] hash_seeds;
    }
    void update(KEY, uint32_t);
    int estimate(KEY);
    std::unordered_set<KEY, KEYHash, KEYEqual> get_result(uint32_t);
};

#endif //MVSKETCH_H
