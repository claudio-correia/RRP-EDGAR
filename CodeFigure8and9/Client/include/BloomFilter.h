#pragma once
#include <vector>
#include <iostream>
#include <array>
#include "MurmurHash3.h"

using namespace std;



struct BloomFilter
{

    public:
        int my_epoch;

        BloomFilter();
        BloomFilter(uint64_t size, uint8_t numHashes, int myEpoch);
        void init(uint64_t size, uint8_t _numHashes);
        void add(const uint8_t *data, std::size_t len);
        bool possiblyContains(const uint8_t *data, std::size_t len) const;
        
        uint8_t m_numHashes;
        std::vector<bool> m_bits;
}; 