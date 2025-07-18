#ifndef SKETCH_H
#define SKETCH_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unordered_map>
#include <unordered_set>
#define MAX(a,b) ((a)<(b))?(b):(a)

class Sketch {
public:
    virtual void update(uint64_t, uint32_t) = 0;
    virtual int estimate(uint64_t) = 0;
    virtual std::unordered_set<uint64_t> get_result(uint32_t) = 0;
};

#endif //SKETCH_H
