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
- On-heap filters (`BinaryFuse8`, `BinaryFuse16`) are the fast, recommended query path.
  A serialized filter can also be queried in place from a `ByteBuffer` (for example a
  memory-mapped file); that saves heap but is slower (see [Performance](#performance)).

## Maven

```xml
<dependency>
  <groupId>io.github.fastfilter</groupId>
  <artifactId>jbinfuse</artifactId>
  <version>0.0.1</version>
</dependency>
```

Gradle: `implementation("io.github.fastfilter:jbinfuse:0.0.1")`

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
`InvalidFilterException` on corrupt or invalid input. This is the recommended way to use a
saved filter: on-heap filters are the fast query path.

`filter.serialize(ByteBuffer)` writes into any buffer (for example a writable
`MappedByteBuffer`, or at an offset inside a larger file); `filter.serializedSize()` tells you
how many bytes it needs. `load(ByteBuffer)` reads from the buffer's position.

### Querying in place (saves heap, costs latency)

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

Use it only when heap is the constraint. **A memory-mapped filter trades query latency for
heap:** in end-to-end primary-key lookups in Lucene on a Xeon Gold 6548N, reading fingerprints
from a mapped file was about 7 ns slower per probe than an on-heap array (10-25% slower lookups
for absent keys, about 7% slower at 100 million keys). A plausible but unverified cause is TLB
misses on 4 KiB page-cache pages, whereas a large Java heap typically uses 2 MiB transparent
huge pages. Views give exactly the same answers as on-heap filters. `wrap` validates the header
(including its checksum) in constant time but does not checksum the fingerprints; the view is
valid only as long as the buffer's bytes are not modified.

## API summary

| Type | Members |
| --- | --- |
| `BinaryFuse8`, `BinaryFuse16` | `build(long[])`, `buildFromBytes(Collection<byte[]>)` |
| `BinaryFuseFilter` (interface) | `contains(long)`, `contains(byte[])`, `contains(byte[], int, int)`, `contains(ByteBuffer)`, `fingerprintBits()`, `keyCount()`, `serializedSize()`, `serialize(ByteBuffer)`, `toByteArray()`; static `wrap(ByteBuffer)`, `load(ByteBuffer)`, `load(byte[])` |
| `WyHash` | `hash(byte[])`, `hash(byte[], int, int)`, `hash(byte[], int, int, long)`, `hash(ByteBuffer)`, `hash(ByteBuffer, int, int, long)`, `hash64(long, long)` |
| `InvalidFilterException` | thrown for corrupt or invalid serialized input |

All filters are immutable and safe for concurrent queries.

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
[Querying in place](#querying-in-place-saves-heap-costs-latency)).

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
reference C implementation by `tools/wyhash_vectors.c` (see the comment at the top of that file).

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
`MAVEN_PASSWORD` (a Central Portal user token for the `io.github.fastfilter` namespace).

## License

Apache License 2.0; see [LICENSE](LICENSE). The wyhash algorithm is by Wang Yi and is in the
public domain.

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
