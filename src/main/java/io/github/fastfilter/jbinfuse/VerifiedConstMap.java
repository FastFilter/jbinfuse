package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.List;

/**
 * An immutable map from keys (strings or byte sequences) to 64-bit values that detects
 * missing keys, in about 18 bytes per key, without storing the keys. Next to the array of
 * values of a {@link ConstMap} it keeps an array of 64-bit check words: a lookup returns
 * {@link #NOT_FOUND} for a key that was not in the map, except with probability about
 * 2<sup>-64</sup>.
 *
 * <p>A lookup of a present key reads three check words and three values, in two arrays. A
 * lookup of a missing key usually stops after the check words, so this layout is the better
 * one when most keys looked up are missing; {@link PairedVerifiedConstMap} stores each value
 * next to its check word and is faster when most are present. {@link #paired()} converts.
 *
 * <p>This is a Java implementation of the {@code VerifiedConstMap} of
 * <a href="https://github.com/lemire/constmap">constmap</a> (Go). Its serialized form
 * ({@code VMAP0001}) is shared with constmap, rsconstmap (Rust) and fastconstmap (C and
 * Python), and for the same keys and values the maps built here serialize to exactly the
 * bytes that the Go and Rust implementations write. See {@link ConstMap} for how keys are
 * hashed, and for the two implementations: on-heap maps and in-place views
 * ({@link #wrap(ByteBuffer)}).
 *
 * <p>Instances are immutable and thread-safe (a view, as long as its buffer's bytes are not
 * modified).
 */
public sealed interface VerifiedConstMap permits HeapVerifiedConstMap, BufferVerifiedConstMap {
  /**
   * The value returned for a key that is not in the map: all 64 bits set ({@code -1}, or
   * 2<sup>64</sup>-1 read as unsigned). A key mapped to this value cannot be told apart from a
   * missing key.
   */
  long NOT_FOUND = ConstMaps.NOT_FOUND;

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
  static VerifiedConstMap build(List<String> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return HeapVerifiedConstMap.build(ConstMaps.hashStrings(keys), values);
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
  static VerifiedConstMap buildFromBytes(List<byte[]> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return HeapVerifiedConstMap.build(ConstMaps.hashBytes(keys), values);
  }

  /**
   * Builds a map from the XXH64 hashes of the keys ({@link XxHash64#hash(byte[])}) and their
   * values. Neither array is modified.
   *
   * @param keyHashes the XXH64 hashes (seed 0) of the keys, distinct
   * @param values the values, one per key
   * @return the on-heap map
   * @throws IllegalArgumentException if the lengths differ, if two hashes are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  static VerifiedConstMap buildFromHashes(long[] keyHashes, long[] values) {
    ConstMaps.checkLengths(keyHashes.length, values.length);
    return HeapVerifiedConstMap.build(keyHashes, values);
  }

  /**
   * Reads a serialized map ({@code VMAP0001}) starting at the buffer's position into a new
   * on-heap map, after validating its header and checksum. The buffer's position is not
   * changed.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return the on-heap map
   * @throws InvalidFilterException if the input is not a valid {@code VerifiedConstMap} or is
   *     corrupt
   */
  static VerifiedConstMap load(ByteBuffer buffer) {
    return HeapVerifiedConstMap.read(buffer);
  }

  /**
   * Reads a serialized map, as {@link #load(ByteBuffer)} does.
   *
   * @param bytes the serialized map
   * @return the on-heap map
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  static VerifiedConstMap load(byte[] bytes) {
    return load(ByteBuffer.wrap(bytes));
  }

  /**
   * Returns a map that queries the serialized map ({@code VMAP0001}) starting at the buffer's
   * position directly, without copying it. The buffer may be on the heap, direct or a
   * {@link java.nio.MappedByteBuffer}; its position, limit and byte order are not changed.
   * There is no alignment requirement.
   *
   * <p>This method runs in constant time: it validates the header but does not verify the
   * checksum (use {@link #load(ByteBuffer)} for that). See {@link ConstMap#wrap(ByteBuffer)}.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return a view backed by the buffer
   * @throws InvalidFilterException if the header is invalid or the buffer is too short
   */
  static VerifiedConstMap wrap(ByteBuffer buffer) {
    return BufferVerifiedConstMap.wrap(buffer);
  }

  /**
   * Returns the value of a key whose XXH64 hash (seed 0) is given. Equivalent to the other
   * {@code get} methods on the key itself.
   *
   * @param keyHash the XXH64 hash of the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  long getByHash(long keyHash);

  /**
   * Returns the value of a string key (hashed through its UTF-8 encoding).
   *
   * @param key the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  default long get(String key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns the value of a byte-array key.
   *
   * @param key the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
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
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
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
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  default long get(ByteBuffer key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns whether a string key is in the map, that is, whether {@link #get(String)} does not
   * return {@link #NOT_FOUND}.
   *
   * @param key the key
   * @return true if the key is in the map (or, with probability about 2<sup>-64</sup>, a
   *     false positive), false if it is not or if its value is {@link #NOT_FOUND}
   */
  default boolean containsKey(String key) {
    return get(key) != NOT_FOUND;
  }

  /**
   * Looks up many string keys at once: {@code dst[i]} receives the value of
   * {@code keys.get(i)}, exactly as {@link #get(String)} would return it. Hashing every key
   * of a block before reading the arrays lets the processor overlap the memory accesses of
   * several lookups.
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
   * @return the values, one per key, {@link #NOT_FOUND} for missing keys
   */
  default long[] getMany(List<String> keys) {
    long[] dst = new long[keys.size()];
    getMany(keys, dst);
    return dst;
  }

  /**
   * Returns the same map in the paired layout, as a new on-heap map (also for a view).
   *
   * @return a {@link PairedVerifiedConstMap} giving the same answers
   */
  PairedVerifiedConstMap paired();

  /**
   * Returns the number of positions in each of the map's two arrays: about 1.125 per key for
   * large maps, more for small ones.
   *
   * @return the array length
   */
  int arrayLength();

  /**
   * Returns the number of bytes written by {@link #serialize(ByteBuffer)}: a 32-byte header,
   * the two arrays, and an 8-byte checksum.
   *
   * @return the serialized size in bytes
   */
  int serializedSize();

  /**
   * Writes the map at the buffer's current position and advances the position by
   * {@link #serializedSize()}. An on-heap map writes the {@code VMAP0001} format shared with
   * the Go, Rust and C implementations; a view writes the bytes it wraps, unchanged. The
   * buffer's byte order is ignored and left unchanged.
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
