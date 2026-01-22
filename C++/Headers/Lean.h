#ifndef LEAN_H
#define LEAN_H
#include "Sketch.h"

class Lean : public Sketch {
private:
    uint32_t m1, m2;
    KEY *HK1, *HK2, *ID2;
    uint32_t *HT1, *HT2;
    int *Count;
    uint32_t bucket_seed1, bucket_seed2;
public:
    Lean(uint32_t, uint32_t);
    ~Lean() {
        delete[] HK1;
        delete[] HK2;
        delete[] ID2;
        delete[] HT1;
        delete[] HT2;
        delete[] Count;
    }
    void update(KEY, uint32_t);
    int estimate(KEY);
    std::unordered_set<KEY, KEYHash, KEYEqual> get_result(uint32_t);
};

#endif //LEAN_H
