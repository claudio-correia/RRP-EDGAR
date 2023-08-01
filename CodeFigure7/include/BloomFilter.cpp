#include "BloomFilter.h"

std::array<uint64_t, 2> hashBF(const uint8_t *data,
                             std::size_t len) {
  std::array<uint64_t, 2> hashValue;
  MurmurHash3_x64_128(data, len, 0, hashValue.data());

  return hashValue;
}

inline uint64_t nthHash(uint8_t n,
                        uint64_t hashA,
                        uint64_t hashB,
                        uint64_t filterSize) {
    //cout << "\n(" << hashA << " + " << (int)n  << "*" << hashB << ") % " << filterSize << "  ==  (" << hashA + n * hashB<< ") % " <<filterSize << " = " << (hashA + n * hashB) % filterSize ;  
    
    return (hashA + n * hashB) % filterSize;
}



BloomFilter::BloomFilter(){
  return;
}


BloomFilter::BloomFilter(uint64_t size, uint8_t numHashes, int myEpoch)
      : m_bits(size),
        m_numHashes(numHashes),
        my_epoch(myEpoch) {}


void BloomFilter::init(uint64_t size, uint8_t _numHashes) {
    m_numHashes = _numHashes;
    m_bits = std::vector<bool>(size);
}


void BloomFilter::add(const uint8_t *data, std::size_t len) {
  std::array<uint64_t, 2>  hashValues = hashBF(data, len);

  for (int n = 0; n < m_numHashes; n++) {
      m_bits[nthHash(n, hashValues[0], hashValues[1], m_bits.size())] = true;
  }
}

bool BloomFilter::possiblyContains(const uint8_t *data, std::size_t len) const {
  std::array<uint64_t, 2>  hashValues = hashBF(data, len);

  for (int n = 0; n < m_numHashes; n++) {
      if (!m_bits[nthHash(n, hashValues[0], hashValues[1], m_bits.size())]) {
          return false;
      }
  }

  return true;
}





bool BloomFilter::possiblyContainsHashMap(int index) const {
  
  for (int n = 0; n < m_numHashes; n++) {
      if (!m_bits[index]) {
          return false;
      }
  }

  return true;
}


bool BloomFilter::possiblyContainsIndexModular(int index) const {
  
  return (index) % m_bits.size();;
}



bool BloomFilter::possiblyContainsModular(const uint8_t *data, std::size_t len) const {
  
  std::array<uint64_t, 2>  hashValues = hashBF(data, len);
  for (int n = 0; n < m_numHashes; n++) {
      nthHash(n, hashValues[0], hashValues[1], m_bits.size());
      
  }

  return true;
}









