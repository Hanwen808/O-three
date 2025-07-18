#ifndef LEANCF_H
#define LEANCF_H
#include "Sketch.h"
#define MAXKICK 10

class LeanCF : public Sketch {
private:
    uint32_t m1, m2;
    uint32_t *ID1;
    uint64_t *ID2;
    uint32_t *Seqs;
    int *Count;
    uint32_t hash_seed;
    uint32_t hash_seed2;
    uint32_t kicked_num = 0;
public:
    LeanCF(uint32_t, uint32_t);
    ~LeanCF() {
        delete[] ID1;
        delete[] ID2;
        delete[] Seqs;
        delete[] Count;
    }
    void update(uint64_t, uint32_t);
    void evict(uint32_t, uint32_t, uint32_t);
    int estimate(uint64_t);
    std::unordered_set<uint64_t> get_result(uint32_t);
};


#endif //LEANCF_H
