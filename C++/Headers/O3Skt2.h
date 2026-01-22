//
// Created by Hanwen on 2025/7/3.
//

#ifndef O3SKT2_H
#define O3SKT2_H
#define TT 16
#include "Sketch.h"

class O3Skt2 : public Sketch {
private:
    uint32_t d, m1; // m2;
    KEY **ID1; // *ID2;
    uint32_t **Count1, **MaxSeq1, **Count2; //*MaxSeq2;
    //uint8_t  *Count2;
    uint32_t *hash_seeds;
    uint32_t resubmit_cnt;
    uint32_t total_pkt;
    uint32_t phi;
public:
    O3Skt2(uint32_t, uint32_t, uint32_t);
    ~O3Skt2() {
        // delete[] ID2;
        // delete[] Count2;
        delete[] hash_seeds;
        for (int i = 0; i < d; ++i) {
            delete[] Count1[i];
            delete[] Count2[i];
            delete[] ID1[i];
            delete[] MaxSeq1[i];
        }
    }
    void update(KEY, uint32_t);
    int estimate(KEY);
    std::unordered_set<KEY, KEYHash, KEYEqual> get_result(uint32_t);
};

#endif //O3SKT2_H
