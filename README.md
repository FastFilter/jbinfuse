# jbinfuse

[![CI](https://github.com/FastFilter/jbinfuse/actions/workflows/ci.yml/badge.svg)](https://github.com/FastFilter/jbinfuse/actions/workflows/ci.yml)

A small, fast Java library of **binary fuse filters**, with no dependencies.

A binary fuse filter is an immutable approximate set: you build it once from a set of keys,
and it then answers "is this key in the set?" with no false negatives and a small,
fixed false-positive probability. Binary fuse filters are smaller than Bloom, cuckoo and xor
filters for the same false-positive rate, and a query reads exactly three memory locations.

- 8-bit fingerprints (`BinaryFuse8`): about 9.0 bits per key, false-positive rate about
  2<sup>-8</sup> (0.39%).
- 16-bit fingerprints (`BinaryFuse16`): about 18.0 bits per key, false-positive rate about
  2<sup>-16</sup> (0.0015%).
- 64-bit keys, or byte-array keys hashed with [wyhash](https://github.com/wangyi-fudan/wyhash)
  (bit-exact with the C reference, final version 4.3).
- A versioned, checksummed, little-endian serialization format.
- Two query modes with identical answers: **on-heap** filters (`BinaryFuse8`,
  `BinaryFuse16`), the fastest; and **in-place views** of a serialized filter in a
  `ByteBuffer` (heap, direct, or a memory-mapped file), with near-zero heap use and instant
  open. See [Choosing a query mode](#choosing-a-query-mode).
- **Constant maps** from string or byte-array keys to 64-bit values, built on the same
  construction (about 9 or 18 bytes per key), whose files are interchangeable with the Go,
  Rust and C/Python implementations. See [Constant maps](#constant-maps).

## Maven

```xml
<dependency>
  <groupId>me.lemire.fastfilter</groupId>
  <artifactId>jbinfuse</artifactId>
  <version>0.0.2</version>
</dependency>
```

Gradle: `implementation("me.lemire.fastfilter:jbinfuse:0.0.2")`

Version 0.0.2 is the first version published to Maven Central. Version 0.0.1 was tagged but
never published: Central rejected its `io.github.fastfilter` groupId.

Requires Java 21 or later.

## Usage

### Build from 64-bit keys

```java
import io.github.fastfilter.jbinfuse.BinaryFuse8;
import io.github.fastfilter.jbinfuse.BinaryFuse16;
import io.github.fastfilter.jbinfuse.BinaryFuseFilter;

long[] keys = {1, 2, 3, 42, 1L << 40};
BinaryFuseFilter filter = BinaryFuse8.build(keys);   // or BinaryFuse16.build(keys)

filter.contains(42);    // true: no false negatives
filter.contains(43);    // false, except with probability about 1/256
```

The input array is not modified, duplicate keys are allowed, and construction is
deterministic (the same keys always give the same filter bytes). If your keys are already
well-distributed 64-bit values this is all you need; otherwise the filter mixes them with
`WyHash.hash64` and the filter's seed, so sequential or structured `long` keys are fine too.

### Build from byte-array keys

```java
import java.nio.charset.StandardCharsets;
import java.util.List;

List<byte[]> keys = List.of(
    "apple".getBytes(StandardCharsets.UTF_8),
    "banana".getBytes(StandardCharsets.UTF_8));
BinaryFuseFilter filter = BinaryFuse16.buildFromBytes(keys);

filter.contains("apple".getBytes(StandardCharsets.UTF_8));   // true
filter.contains(buffer, offset, length);                      // a byte[] range
filter.contains(byteBuffer);                                  // bytes from position to limit
```

Byte keys are hashed to 64 bits with `WyHash.hash(bytes)` (seed 0), so
`contains(bytes) == contains(WyHash.hash(bytes))`. You can hash keys yourself (for example
while streaming them) and call `BinaryFuse8.build(long[])` with the hashes.

### Save to a file and load it back

```java
import java.nio.file.Files;
import java.nio.file.Path;

Files.write(Path.of("filter.bin"), filter.toByteArray());

BinaryFuseFilter loaded = BinaryFuseFilter.load(Files.readAllBytes(Path.of("filter.bin")));
loaded.contains(42);
```

`load` copies the filter to the heap after full validation (magic bytes, format version,
variant, parameters, and CRC32C checksums of the header and of the fingerprints) and throws
`InvalidFilterException` on corrupt or invalid input. On-heap filters are the default and the
fastest query path.

`filter.serialize(ByteBuffer)` writes into any buffer (for example a writable
`MappedByteBuffer`, or at an offset inside a larger file); `filter.serializedSize()` tells you
how many bytes it needs. `load(ByteBuffer)` reads from the buffer's position.

### Query in place from a memory-mapped file

`BinaryFuseFilter.wrap(ByteBuffer)` returns a view that queries the serialized bytes in place,
without copying them, from a heap, direct or memory-mapped buffer:

```java
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;

try (FileChannel ch = FileChannel.open(Path.of("filter.bin"), StandardOpenOption.READ)) {
  MappedByteBuffer mapped = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size());
  BinaryFuseFilter view = BinaryFuseFilter.wrap(mapped);   // constant time, no copy
  view.contains(42);
}
```

The mapping stays valid after the channel is closed. `wrap` validates the header (including
its checksum) in constant time but does not checksum the fingerprints; the view is valid only
as long as the buffer's bytes are not modified. Views give exactly the same answers as
on-heap filters (this is tested, including over memory-mapped files).

### Choosing a query mode

| | on-heap (`build`, `load`) | in place (`wrap`) |
| --- | --- | --- |
| query latency | fastest | slower: about +7 ns per probe from a mapped file |
| heap use | the whole filter (about 1.1 or 2.3 bytes per key) | near zero |
| opening a saved filter | reads and checksums the whole file | instant (constant time) |
| validation | full (header and fingerprint checksums) | header only |

On-heap is the default and what the examples use. In end-to-end primary-key lookups in Lucene
on a Xeon Gold 6548N, reading fingerprints from a memory-mapped file cost about 7 ns more per
probe than an on-heap array: about 25% slower for absent keys across 8 segments, 10-20% in a
single segment, and about 7% at 100 million keys. (A plausible but unverified cause is TLB
misses on 4 KiB page-cache pages, whereas a large Java heap typically uses 2 MiB transparent
huge pages.) Choose `wrap` when heap memory or open time matters more than those nanoseconds,
for example for many large filters.

## Constant maps

The binary fuse construction also gives an immutable map from keys to 64-bit values that does
not store the keys: a lookup is one hash, three array reads and two XORs.

```java
import io.github.fastfilter.jbinfuse.ConstMap;
import io.github.fastfilter.jbinfuse.VerifiedConstMap;

List<String> keys = List.of("apple", "banana", "cherry");
long[] values = {100, 200, 300};

ConstMap cm = ConstMap.build(keys, values);          // about 9 bytes per key
cm.get("banana");                                    // 200
cm.get("grape");                                     // an arbitrary value!

VerifiedConstMap vm = VerifiedConstMap.build(keys, values);   // about 18 bytes per key
vm.get("banana");                                    // 200
vm.get("grape");                                     // VerifiedConstMap.NOT_FOUND (-1)
vm.containsKey("grape");                             // false

long[] many = vm.getMany(List.of("apple", "grape")); // {100, NOT_FOUND}
```

| | `ConstMap` | `VerifiedConstMap` | `PairedVerifiedConstMap` |
| --- | --- | --- | --- |
| bytes per key | about 9 | about 18 | about 18 |
| missing key | arbitrary value | `NOT_FOUND` | `NOT_FOUND` |
| cache lines per lookup | 3 | 6 (3 for most misses) | 3 |
| best when | you only look up keys in the map | most lookups miss | most lookups hit |

Keys must be distinct. String keys are hashed through their UTF-8 encoding with XXH64
(`XxHash64`), so `get("abc")` and `get("abc".getBytes(UTF_8))` are the same lookup; there are
also `buildFromBytes(List<byte[]>, long[])`, `get(byte[], int, int)`, `get(ByteBuffer)`, and
`buildFromHashes`/`getByHash` taking XXH64 hashes you computed yourself. A verified map reports
a missing key as present with probability about 2<sup>-64</sup>; a key whose value is
`NOT_FOUND` cannot be told apart from a missing one. `vm.paired()` converts a
`VerifiedConstMap` to a `PairedVerifiedConstMap`.

`getMany` hashes a block of keys before reading the array, so that the processor can overlap
the memory accesses of several lookups; it returns exactly what a loop over `get` would.

### Interoperability with constmap, rsconstmap and fastconstmap

These classes are a Java implementation of [constmap](https://github.com/lemire/constmap) (Go),
also implemented by [rsconstmap](https://github.com/lemire/rsconstmap) (Rust) and
[fastconstmap](https://github.com/lemire/fastconstmap) (C, with Python bindings). All four
share the key hash, the mixing, the seed sequence, the layout and the file formats, so a map
saved by any of them loads in the others:

```java
Files.write(Path.of("map.vmap"), vm.toByteArray());                    // Go, Rust, Python read it
VerifiedConstMap fromPython = VerifiedConstMap.load(Files.readAllBytes(Path.of("built-by-python.vmap")));
```

- For the same keys and values, the Java classes write exactly the bytes that Go and Rust
  write: `CMAP0001`, `VMAP0001` and `PMAP0001`. This is tested against the files of the other
  implementations and against the Go package for sizes from 0 to 1,234,567 keys.
- `ConstMap.load` also reads fastconstmap's `CMAP0003` (the same format with a key count,
  which is ignored). fastconstmap's key count in the padding word of the other two formats is
  ignored too.
- Files from fastconstmap 0.9 and earlier (`CMAP0002`, `VCMP0002`) used another hash (XXH3)
  and are refused with a message saying so; rebuild them with fastconstmap 0.10 or later.
- `load` validates the magic bytes, the segment parameters and the FNV-1a checksum, and throws
  `InvalidFilterException` otherwise, including for a file of another kind of map.

### Querying a constant map in place

As with filters, `wrap(ByteBuffer)` returns a view that queries a serialized map in place,
without copying it, from a heap, direct or memory-mapped buffer. It reads every format above,
written by any of the four implementations:

```java
try (FileChannel ch = FileChannel.open(Path.of("built-by-go.vmap"), StandardOpenOption.READ)) {
  MappedByteBuffer mapped = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size());
  VerifiedConstMap view = VerifiedConstMap.wrap(mapped);   // constant time, no copy
  view.get("banana");
}
```

- Views give the same answers as on-heap maps, including `getMany` and `paired()` (which
  returns a new on-heap map). This is tested on the files written by rsconstmap and
  fastconstmap, at every alignment, in heap, direct and memory-mapped buffers.
- There is no alignment requirement. A Go or Rust `ConstMap` file (`CMAP0001`), whose 28-byte
  header leaves the array 4 bytes off an 8-byte boundary, can be wrapped too, at any offset;
  fastconstmap's `from_buffer` refuses those files.
- `wrap` validates the header in constant time (magic bytes, segment parameters consistent
  with the array length, and a buffer long enough for the whole map) but does not verify the
  checksum, which would read the whole map; `load` does. On corrupt bytes, a view gives wrong
  answers but never reads outside the map.
- A view serializes to the bytes it wraps, unchanged (so a `CMAP0003` file from fastconstmap
  stays one, and keeps its key count). On-heap maps write the formats of Go and Rust.
- The view is valid as long as the buffer's bytes are not modified. The buffer's position,
  limit and byte order are not changed.

On an Intel Xeon Gold 6548N (JDK 25, one pinned core, `ConstMapBenchmark`), ns per lookup of
a present string key in random order, on-heap map against views of a direct buffer and of a
memory-mapped file:

| | keys | heap | direct | mapped |
| --- | ---: | ---: | ---: | ---: |
| `ConstMap.get` | 1M | 38.9 | 41.3 | 44.5 |
| | 10M | 44.7 | 46.6 | 54.8 |
| `VerifiedConstMap.get` | 1M | 43.4 | 47.5 | 54.9 |
| | 10M | 49.7 | 51.6 | 66.2 |
| `PairedVerifiedConstMap.get` | 1M | 42.9 | 44.6 | 51.3 |
| | 10M | 47.8 | 48.2 | 59.1 |
| `ConstMap.getMany` | 1M | 29.0 | 30.1 | 31.1 |
| | 10M | 30.3 | 31.0 | 35.9 |
| `VerifiedConstMap.getMany` | 1M | 34.9 | 35.2 | 38.8 |
| | 10M | 35.8 | 37.1 | 49.4 |
| `PairedVerifiedConstMap.getMany` | 1M | 31.8 | 31.8 | 33.9 |
| | 10M | 32.9 | 32.9 | 37.8 |

A direct buffer costs 0 to 4 ns per lookup over the heap. A memory-mapped file costs more, up
to 10 to 16 ns at ten million keys for the verified map, which reads two arrays; `getMany`
and the paired layout recover most of it. As with filters, choose views when heap use or
opening time matters more than those nanoseconds.

### Constant map performance

JMH (`ConstMapBenchmark`, on-heap maps) on an Apple M4 Max with JDK 27, ns per lookup of a present key, in
random order, with keys like `key-123456-1e3779b9`:

| | 1 million keys | 10 million keys |
| --- | ---: | ---: |
| `ConstMap.get(String)` | 16.7 | 33.0 |
| `ConstMap.getMany` | 16.2 | 24.8 |
| `VerifiedConstMap.get(String)` | 25.8 | 65.4 |
| `VerifiedConstMap.getMany` | 20.1 | 38.1 |
| `PairedVerifiedConstMap.get(String)` | 23.1 | 44.9 |
| `PairedVerifiedConstMap.getMany` | 20.7 | 28.9 |

About 12 ns of a lookup at one million keys is hashing the string. ASCII strings are hashed
straight from their chars; other strings are first encoded to UTF-8, which costs more.
`get(byte[])` with a ready byte array takes about 11.8 ns at one million keys.

## API summary

| Type | Members |
| --- | --- |
| `BinaryFuse8`, `BinaryFuse16` | `build(long[])`, `build(long[], int)`, `buildFromBytes(Collection<byte[]>)` |
| `BinaryFuseFilter` (interface) | `contains(long)`, `contains(byte[])`, `contains(byte[], int, int)`, `contains(ByteBuffer)`, `fingerprintBits()`, `keyCount()`, `serializedSize()`, `serialize(ByteBuffer)`, `toByteArray()`; static `wrap(ByteBuffer)`, `load(ByteBuffer)`, `load(byte[])` |
| `ConstMap` (interface) | static `build(List<String>, long[])`, `buildFromBytes(List<byte[]>, long[])`, `buildFromHashes(long[], long[])`, `load(ByteBuffer)`, `load(byte[])`, `wrap(ByteBuffer)`; `get(String)`, `get(byte[])`, `get(byte[], int, int)`, `get(ByteBuffer)`, `getByHash(long)`, `getMany(List<String>)`, `getMany(List<String>, long[])`, `arrayLength()`, `serializedSize()`, `serialize(ByteBuffer)`, `toByteArray()` |
| `VerifiedConstMap` (interface) | as `ConstMap`, plus `containsKey(String)`, `paired()` and the constant `NOT_FOUND` |
| `PairedVerifiedConstMap` (interface) | as `ConstMap`, plus `containsKey(String)` |
| `XxHash64` | `hash(String)`, `hash(byte[])`, `hash(byte[], int, int)`, `hash(byte[], int, int, long)`, `hash(ByteBuffer)`, `hash(ByteBuffer, int, int, long)` |
| `WyHash` | `hash(byte[])`, `hash(byte[], int, int)`, `hash(byte[], int, int, long)`, `hash(ByteBuffer)`, `hash(ByteBuffer, int, int, long)`, `hash64(long, long)` |
| `InvalidFilterException` | thrown for corrupt or invalid serialized input |

All filters and maps are immutable and safe for concurrent queries.

## Size and false-positive rate

Measured with random 64-bit keys and 50 million random negative queries
(sizes include the 40-byte header):

| keys | `BinaryFuse8` bits/key | `BinaryFuse8` FPR | `BinaryFuse16` bits/key | `BinaryFuse16` FPR |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 11.6 | 0.39% | 22.9 | 0.0014% |
| 10,000 | 10.3 | 0.39% | 20.5 | 0.0016% |
| 100,000 | 9.5 | 0.39% | 19.0 | 0.0015% |
| 1,000,000 | 9.0 | 0.39% | 18.1 | 0.0015% |
| 10,000,000 | 9.0 | 0.39% | 18.0 | 0.0016% |

The theoretical false-positive rates are 1/256 = 0.39% and 1/65536 = 0.0015%. A Bloom filter
with the same false-positive rate needs about 11.5 (respectively 23) bits per key.

## Performance

JMH results on an Intel Xeon Gold 6548N (Linux, JDK 21, one pinned core), random 64-bit keys,
queries half hits and half misses:

| operation | 1 million keys | 10 million keys |
| --- | ---: | ---: |
| `contains(long)`, `BinaryFuse8` on heap | 4.1 ns | 7.7 ns |
| `contains(long)`, `BinaryFuse16` on heap | 6.3 ns | 7.8 ns |
| `contains(long)`, 8-bit view of a direct `ByteBuffer` | 5.0 ns | 8.3 ns |
| `contains(long)`, 16-bit view of a direct `ByteBuffer` | 7.4 ns | 8.6 ns |
| construction, 8-bit or 16-bit | 48 ms (48 ns/key) | 550 ms (55 ns/key) |

On-heap filters are the fastest. Even in this microbenchmark, where the whole filter is hot,
views over a direct `ByteBuffer` are 0.6 to 1 ns slower per query; with a memory-mapped file
in a real application the gap was larger, about 7 ns per probe (see
[Choosing a query mode](#choosing-a-query-mode)).

Hashing a 16-byte key with `WyHash.hash` takes about 5.4 ns (8 bytes: 5.3 ns, 32 bytes:
6.8 ns, 100 bytes: 11.5 ns).

Construction uses about 25 bytes of transient memory per key (as in the C reference), plus the
filter itself. Keys are not sorted: the library only sorts and deduplicates (a copy of) the keys
if a construction attempt fails, which in practice only happens when the input has duplicates
that could not be filtered out cheaply. Construction typically succeeds on the first attempt
and essentially never needs more than a few.

Run the benchmarks yourself (they are a separate, unreleased Maven project):

```
./mvnw -f benchmarks/pom.xml package
java -jar benchmarks/target/benchmarks.jar
```

## Design notes

- **Algorithm.** Arity-3 binary fuse filters exactly as in the C
  ([xor_singleheader](https://github.com/FastFilter/xor_singleheader)) and Go
  ([xorfilter](https://github.com/FastFilter/xorfilter)) references: segment length
  `1 << floor(ln(n)/ln(3.33) + 2.25)` capped at 2<sup>18</sup>, size factor
  `max(1.125, 0.875 + 0.25 ln(10^6)/ln(n))`, fingerprint `hash ^ (hash >>> 32)`, and seeds from
  a deterministic splitmix64 sequence. The per-key hash is `WyHash.hash64(key, seed)`.
- **Why Java 21.** Java 21 is the current long-term-support baseline used by our other
  libraries (for example JavaFastPFOR). It gives us `Math.unsignedMultiplyHigh` (an intrinsic
  for the 64x64->128-bit products in wyhash and in the filter's range reduction), records and
  sealed interfaces. The foreign-memory API (`MemorySegment`) only became final in Java 22, so
  off-heap access uses `ByteBuffer` absolute little-endian reads instead, which work equally for
  heap, direct and memory-mapped buffers. One consequence is that a single serialized filter is
  limited to 2 GiB (about 1.9 billion keys with 8-bit fingerprints, half that with 16-bit
  fingerprints).

## Serialization format (version 1)

All integers are little-endian. A filter is a 40-byte header followed by the fingerprints.

| offset | size | field |
| ---: | ---: | --- |
| 0 | 4 | magic bytes `JBFU` |
| 4 | 1 | format version (1) |
| 5 | 1 | fingerprint bits (8 or 16) |
| 6 | 1 | arity (3) |
| 7 | 1 | flags (0) |
| 8 | 8 | seed |
| 16 | 4 | number of distinct keys |
| 20 | 4 | segment length (power of two, 4 to 2<sup>18</sup>) |
| 24 | 4 | segment count |
| 28 | 4 | array length = (segment count + 2) x segment length (0 if there are no keys) |
| 32 | 4 | CRC32C of the fingerprints |
| 36 | 4 | CRC32C of bytes 0 to 35 |
| 40 | array length x 1 or 2 | fingerprints (unsigned 8-bit or 16-bit little-endian) |

Bytes after the filter are ignored, so filters can be embedded in larger files. Future versions
of the library will keep reading version 1.

## Building and testing

```
./mvnw package          # compile, test, build the jar, sources jar and javadoc jar
```

The wyhash test vectors in `src/test/resources/wyhash_vectors.txt` were generated from the
reference C implementation by `tools/wyhash_vectors.c` (see the comment at the top of that file),
and the XXH64 vectors in `src/test/resources/xxh64_vectors.txt` by `tools/xxh64_vectors.c`.
`src/test/resources/constmap_vectors.txt` holds the size and checksum of maps built by the Go
constmap package, written by `tools/constmap_vectors` (`go run .` in that directory), and
`src/test/resources/constmap/` holds the interoperability files of the constmap repository,
written by rsconstmap and fastconstmap.

## Release procedure

Releases are published to Maven Central by the
[Release workflow](.github/workflows/release.yml), the same mechanism as
[JavaFastPFOR](https://github.com/fast-pack/JavaFastPFOR):

1. Make sure `main` is green and the `pom.xml` version is the next `x.y.z-SNAPSHOT`.
2. In GitHub, go to *Actions*, *Release*, *Run workflow* (on `main`), optionally entering a
   release version; or run `gh workflow run release.yml -R FastFilter/jbinfuse`.
3. The workflow runs `mvn release:prepare` (sets the version to `x.y.z`, tags `vx.y.z`, then
   bumps to the next snapshot and pushes both commits and the tag), then `mvn release:perform`,
   which builds the tag, signs the artifacts with GPG and publishes them to the Sonatype
   Central Portal with [Njord](https://github.com/maveniverse/njord), and finally creates a
   GitHub release.

The workflow uses the repository secrets `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `MAVEN_USER` and
`MAVEN_PASSWORD` (a Central Portal user token for the `me.lemire` namespace, which covers the `me.lemire.fastfilter` groupId).

## License

Apache License 2.0; see [LICENSE](LICENSE). The wyhash algorithm is by Wang Yi and is in the
public domain. The XXH64 algorithm is by Yann Collet.

## Reference

Thomas Mueller Graf and Daniel Lemire, *Binary Fuse Filters: Fast and Smaller Than Xor
Filters*, ACM Journal of Experimental Algorithmics 27, 2022.
[doi:10.1145/3510449](https://doi.org/10.1145/3510449),
[arXiv:2201.01174](https://arxiv.org/abs/2201.01174)

```bibtex
@article{graf2022binary,
  title   = {Binary Fuse Filters: Fast and Smaller Than Xor Filters},
  author  = {Graf, Thomas Mueller and Lemire, Daniel},
  journal = {ACM Journal of Experimental Algorithmics},
  volume  = {27},
  year    = {2022},
  doi     = {10.1145/3510449}
}
```
