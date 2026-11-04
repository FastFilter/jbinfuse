// Generates XXH64 test vectors from the reference C implementation of xxHash
// (https://github.com/Cyan4973/xxHash, xxhash.h; any release since 0.8 gives
// the same XXH64 results), for the Java XxHash64 class.
//
// Build and run (from the repository root):
//   cc -O2 -I path/to/xxhash tools/xxh64_vectors.c -o /tmp/xxh64_vectors
//   /tmp/xxh64_vectors > src/test/resources/xxh64_vectors.txt
//
// The input bytes are produced by the same 64-bit LCG as tools/wyhash_vectors.c,
// which the Java test reproduces:
//   state = state * 6364136223846793005 + 1442695040888963407; byte = state >> 56
// Output lines:
//   B <len> <seed hex> <hash hex>      XXH64(data[0..len), len, seed)
//   S <string> <hash hex>              XXH64 of an ASCII string, seed 0
#define XXH_INLINE_ALL
#include <stdio.h>
#include <string.h>
#include "xxhash.h"

int main(void) {
  static uint8_t data[1024];
  uint64_t state = 0x9E3779B97F4A7C15ULL;
  for (int i = 0; i < 1024; i++) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    data[i] = (uint8_t)(state >> 56);
  }
  const uint64_t seeds[] = {0, 1, 0x9E3779B97F4A7C15ULL, 0xFFFFFFFFFFFFFFFFULL};
  for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
    for (int len = 0; len <= 160; len++) {
      printf("B %d %016llx %016llx\n", len, (unsigned long long)seeds[s],
             (unsigned long long)XXH64(data, (size_t)len, seeds[s]));
    }
    for (int len = 161; len <= 1024; len += 37) {
      printf("B %d %016llx %016llx\n", len, (unsigned long long)seeds[s],
             (unsigned long long)XXH64(data, (size_t)len, seeds[s]));
    }
  }
  const char *strings[] = {"", "a", "abc", "apple", "banana", "key-0", "key-199",
                           "The quick brown fox jumps over the lazy dog"};
  for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
    printf("S %s %016llx\n", strings[i],
           (unsigned long long)XXH64(strings[i], strlen(strings[i]), 0));
  }
  return 0;
}
