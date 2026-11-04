// Generates wyhash (final version 4.3) test vectors from the reference C
// implementation, commit e4764a0b637d34d3421a7760affada9288b625a8 of
// https://github.com/wangyi-fudan/wyhash (wyhash.h).
//
// Build and run (from the repository root):
//   cc -O2 -I path/to/wyhash tools/wyhash_vectors.c -o /tmp/wyhash_vectors
//   /tmp/wyhash_vectors > src/test/resources/wyhash_vectors.txt
//
// The input bytes are produced by a 64-bit LCG that the Java test reproduces:
//   state = state * 6364136223846793005 + 1442695040888963407; byte = state >> 56
// Output lines:
//   B <len> <seed hex> <hash hex>      wyhash(data[0..len), len, seed, _wyp)
//   S <string> <hash hex>              wyhash of an ASCII string, seed 0
//   M <a hex> <b hex> <hash hex>       wyhash64(a, b)
#include <stdio.h>
#include <string.h>
#include "wyhash.h"

int main(void) {
  static uint8_t data[1024];
  uint64_t state = 0x9E3779B97F4A7C15ull;
  for (size_t i = 0; i < sizeof(data); i++) {
    state = state * 6364136223846793005ull + 1442695040888963407ull;
    data[i] = (uint8_t)(state >> 56);
  }
  const uint64_t seeds[] = {0, 1, 0x123456789abcdef0ull, 0xffffffffffffffffull, 0x2d358dccaa6c78a5ull};
  for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
    for (size_t len = 0; len <= 300; len++) {
      printf("B %zu %016llx %016llx\n", len, (unsigned long long)seeds[s],
             (unsigned long long)wyhash(data, len, seeds[s], _wyp));
    }
    size_t big[] = {511, 512, 513, 1000, 1024};
    for (size_t k = 0; k < 5; k++) {
      printf("B %zu %016llx %016llx\n", big[k], (unsigned long long)seeds[s],
             (unsigned long long)wyhash(data, big[k], seeds[s], _wyp));
    }
  }
  const char *strs[] = {"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "0000000000000000", "0000000000000001"};
  for (size_t k = 0; k < sizeof(strs) / sizeof(strs[0]); k++) {
    printf("S %s %016llx\n", strs[k], (unsigned long long)wyhash(strs[k], strlen(strs[k]), 0, _wyp));
  }
  uint64_t x = 1;
  for (int k = 0; k < 64; k++) {
    uint64_t a = x, b = x * 0x9E3779B97F4A7C15ull + (uint64_t)k;
    printf("M %016llx %016llx %016llx\n", (unsigned long long)a, (unsigned long long)b,
           (unsigned long long)wyhash64(a, b));
    x = x * 6364136223846793005ull + 1442695040888963407ull;
  }
  printf("M %016llx %016llx %016llx\n", 0ull, 0ull, (unsigned long long)wyhash64(0, 0));
  printf("M %016llx %016llx %016llx\n", ~0ull, ~0ull, (unsigned long long)wyhash64(~0ull, ~0ull));
  return 0;
}
