package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.List;

/**
 * An immutable map from keys (strings or byte sequences) to 64-bit values, in about 9 bytes
 * per key, that does not store the keys. A lookup is one XXH64 hash, three array reads and two
 * XORs.
 *
 * <p>Looking up a key that was not in the map returns an arbitrary value: use
 * {@link VerifiedConstMap} or {@link PairedVerifiedConstMap} if you need to detect missing
 * keys.
 *
 * <p>This is a Java implementation of <a href="https://github.com/lemire/constmap">constmap</a>
 * (Go). Its serialized form is shared with constmap, with
 * <a href="https://github.com/lemire/rsconstmap">rsconstmap</a> (Rust) and with
 * <a href="https://github.com/lemire/fastconstmap">fastconstmap</a> (C and Python): a map
 * built by any of them loads in the others. For the same keys and values, the maps built here
 * serialize to exactly the bytes that the Go and Rust implementations write.
 *
 * <p>There are two implementations with identical answers: on-heap maps, from the
 * {@code build} methods and {@link #load(ByteBuffer)}, which are the fastest; and views from
 * {@link #wrap(ByteBuffer)}, which query a serialized map in place in a heap, direct or
 * memory-mapped buffer, without copying it.
 *
 * <p>String keys are hashed through their UTF-8 encoding, so {@code get("abc")} and
 * {@code get("abc".getBytes(UTF_8))} are the same lookup. Values are 64-bit words; read them as
 * unsigned if you need values above {@link Long#MAX_VALUE}.
 *
 * <p>Instances are immutable and thread-safe (a view, as long as its buffer's bytes are not
 * modified).
 */
public sealed interface ConstMap permits HeapConstMap, BufferConstMap {

  /**
   * Builds a map from string keys and their values: {@code keys.get(i)} maps to
   * {@code values[i]}. Keys must be distinct. Construction is deterministic.
   *
   * @param keys the keys, distinct
   * @param values the values, one per key
   * @return the on-heap map
   * @throws IllegalArgumentException if the lengths differ, if two keys are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  static ConstMap build(List<String> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return HeapConstMap.build(ConstMaps.hashStrings(keys), values);
  }

  /**
   * Builds a map from byte-array keys and their values: {@code keys.get(i)} maps to
   * {@code values[i]}. Keys must be distinct. Construction is deterministic.
   *
   * @param keys the keys, distinct
   * @param values the values, one per key
   * @return the on-heap map
   * @throws IllegalArgumentException if the lengths differ, if two keys are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  static ConstMap buildFromBytes(List<byte[]> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return HeapConstMap.build(ConstMaps.hashBytes(keys), values);
  }

  /**
   * Builds a map from the XXH64 hashes of the keys ({@link XxHash64#hash(byte[])}) and their
   * values, for callers that hash keys as they stream them. Neither array is modified.
   *
   * @param keyHashes the XXH64 hashes (seed 0) of the keys, distinct
   * @param values the values, one per key
   * @return the on-heap map
   * @throws IllegalArgumentException if the lengths differ, if two hashes are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  static ConstMap buildFromHashes(long[] keyHashes, long[] values) {
    ConstMaps.checkLengths(keyHashes.length, values.length);
    return HeapConstMap.build(keyHashes, values);
  }

  /**
   * Reads a serialized map starting at the buffer's position into a new on-heap map, after
   * validating its header and checksum. Accepts both the {@code CMAP0001} format (Go, Rust,
   * this library) and fastconstmap's {@code CMAP0003}, which adds a key count that is
   * ignored. The buffer's position is not changed.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return the on-heap map
   * @throws InvalidFilterException if the input is not a valid {@code ConstMap} (including a
   *     {@code VerifiedConstMap} or {@code PairedVerifiedConstMap}, or a file from
   *     fastconstmap 0.9 or earlier, which used another hash), or is corrupt
   */
  static ConstMap load(ByteBuffer buffer) {
    return HeapConstMap.read(buffer);
  }

  /**
   * Reads a serialized map, as {@link #load(ByteBuffer)} does.
   *
   * @param bytes the serialized map
   * @return the on-heap map
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  static ConstMap load(byte[] bytes) {
    return load(ByteBuffer.wrap(bytes));
  }

  /**
   * Returns a map that queries the serialized map starting at the buffer's position directly,
   * without copying it. The buffer may be on the heap, direct or a
   * {@link java.nio.MappedByteBuffer}; its position, limit and byte order are not changed. It
   * reads the same formats as {@link #load(ByteBuffer)} ({@code CMAP0001} and
   * {@code CMAP0003}), at any offset: there is no alignment requirement.
   *
   * <p>This method runs in constant time: it validates the header (magic bytes, segment
   * parameters consistent with the array length, and a buffer long enough for the whole map)
   * but does not verify the checksum, which would read the whole map; use
   * {@link #load(ByteBuffer)} for that. A view answers like the on-heap map as long as the
   * buffer's bytes are not modified; on corrupt bytes it returns wrong values but never reads
   * outside the map.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return a view backed by the buffer
   * @throws InvalidFilterException if the header is invalid or the buffer is too short
   */
  static ConstMap wrap(ByteBuffer buffer) {
    return BufferConstMap.wrap(buffer);
  }

  /**
   * Returns the value of a key whose XXH64 hash (seed 0) is given. Equivalent to the other
   * {@code get} methods on the key itself.
   *
   * @param keyHash the XXH64 hash of the key
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  long getByHash(long keyHash);

  /**
   * Returns the value of a string key (hashed through its UTF-8 encoding).
   *
   * @param key the key
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  default long get(String key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns the value of a byte-array key.
   *
   * @param key the key
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  default long get(byte[] key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns the value of the key made of {@code len} bytes of {@code key} from {@code off}.
   *
   * @param key the array holding the key
   * @param off the index of its first byte
   * @param len its length
   * @return the value if the key is in the map, an arbitrary value otherwise
   * @throws IndexOutOfBoundsException if the range is not within the array
   */
  default long get(byte[] key, int off, int len) {
    return getByHash(XxHash64.hash(key, off, len));
  }

  /**
   * Returns the value of the key made of the buffer's bytes from its position to its limit.
   * The buffer is not modified.
   *
   * @param key the key
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  default long get(ByteBuffer key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Looks up many string keys at once: {@code dst[i]} receives the value of
   * {@code keys.get(i)}, exactly as {@link #get(String)} would return it. Hashing every key
   * of a block before reading the array lets the processor overlap the memory accesses of
   * several lookups, which helps when the map is larger than the cache.
   *
   * @param keys the keys
   * @param dst where the values go; only the first {@code keys.size()} entries are written
   * @throws IndexOutOfBoundsException if {@code dst} is shorter than {@code keys}
   */
  void getMany(List<String> keys, long[] dst);

  /**
   * Looks up many string keys at once, as {@link #getMany(List, long[])} does, into a new
   * array.
   *
   * @param keys the keys
   * @return the values, one per key
   */
  default long[] getMany(List<String> keys) {
    long[] dst = new long[keys.size()];
    getMany(keys, dst);
    return dst;
  }

  /**
   * Returns the number of 64-bit words in the map's array: about 1.125 per key for large
   * maps, more for small ones.
   *
   * @return the array length
   */
  int arrayLength();

  /**
   * Returns the number of bytes written by {@link #serialize(ByteBuffer)}: for an on-heap map,
   * a 28-byte header, the array and an 8-byte checksum; for a view, the size of the
   * serialized map it wraps.
   *
   * @return the serialized size in bytes
   */
  int serializedSize();

  /**
   * Writes the map at the buffer's current position and advances the position by
   * {@link #serializedSize()}. An on-heap map writes the {@code CMAP0001} format shared with
   * the Go, Rust and C implementations; a view writes the bytes it wraps, unchanged (so a
   * {@code CMAP0003} file from fastconstmap stays one). The buffer's byte order is ignored
   * and left unchanged.
   *
   * @param out the destination
   * @throws java.nio.BufferOverflowException if fewer than {@link #serializedSize()} bytes
   *     remain
   * @throws java.nio.ReadOnlyBufferException if the buffer is read-only
   */
  void serialize(ByteBuffer out);

  /**
   * Returns the serialized form of the map, as written by {@link #serialize(ByteBuffer)}.
   *
   * @return a new array of {@link #serializedSize()} bytes
   */
  default byte[] toByteArray() {
    byte[] bytes = new byte[serializedSize()];
    serialize(ByteBuffer.wrap(bytes));
    return bytes;
  }
}
