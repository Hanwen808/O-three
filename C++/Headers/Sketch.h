//
// Created by Hanwen on 2025/7/2.
//

#ifndef SKETCH_H
#define SKETCH_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unordered_map>
#include <unordered_set>
#define TRICK 5
#define MAX(a,b) ((a)<(b))?(b):(a)

typedef struct tmps {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    bool operator==(const tmps b) const {  
        if (src_ip == b.src_ip && dst_ip == b.dst_ip && sport == b.sport && dport == b.dport) {
            return true;
        } else {
            return false;
        }
    }
    bool is_empty() {
        if (src_ip == 0 && dst_ip == 0 && sport == 0 && dport == 0) {
            return true;
        } else {
            return false;
        }
    }
} KEY;

struct KEYHash {
    std::size_t operator()(const KEY& k) const noexcept {
        std::size_t h1 = std::hash<uint32_t>{}(k.src_ip);
        std::size_t h2 = std::hash<uint32_t>{}(k.dst_ip);
        std::size_t h3 = std::hash<uint16_t>{}(k.sport);
        std::size_t h4 = std::hash<uint16_t>{}(k.dport);
        return ((h1 ^ (h2 << 1)) >> 1) ^ (h3 << 1) ^ h4;
    }
};

struct KEYEqual {
    bool operator()(const KEY& a, const KEY& b) const noexcept {
        return a == b;
    }
};

class Sketch {
public:
    virtual void update(KEY, uint32_t) = 0;
    virtual int estimate(KEY) = 0;
    virtual std::unordered_set<KEY, KEYHash, KEYEqual> get_result(uint32_t) = 0;
};

#endif //SKETCH_H
