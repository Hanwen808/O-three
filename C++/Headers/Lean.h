#ifndef LEAN_H
#define LEAN_H
#include "Sketch.h"

class Lean : public Sketch {
private:
    uint32_t m1, m2;
    uint64_t *ID1, *ID2;
    uint32_t *Seqs;
    int *Count;
    uint32_t hash_seed;
public:
    Lean(uint32_t, uint32_t);
    ~Lean() {
        delete[] ID1;
        delete[] ID2;
        delete[] Seqs;
        delete[] Count;
    }
    void update(uint64_t, uint32_t);
    int estimate(uint64_t);
    std::unordered_set<uint64_t> get_result(uint32_t);
};

#endif //LEAN_H
