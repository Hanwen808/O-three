#ifndef O3SKT_H
#define O3SKT_H
#define TT 16
#include "Sketch.h"

class O3Skt : public Sketch {
private:
    uint32_t d, m1, m2;
    uint64_t **ID1, *ID2;
    uint32_t **Count1, **MaxSeq1, *MaxSeq2;
    uint8_t  *Count2;
    uint32_t *hash_seeds;
public:
    O3Skt(uint32_t, uint32_t, uint32_t);
    ~O3Skt() {
        delete[] ID2;
        delete[] Count2;
        delete[] hash_seeds;
        for (int i = 0; i < d; ++i) {
            delete[] Count1[i];
            delete[] ID1[i];
            delete[] MaxSeq1[i];
        }
    }
    void update(uint64_t, uint32_t);
    int estimate(uint64_t);
    std::unordered_set<uint64_t> get_result(uint32_t);
};

#endif //O3SKT_H
