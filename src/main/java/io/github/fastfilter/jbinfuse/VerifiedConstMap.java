package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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
 * Python), and for the same keys and values this class writes exactly the bytes that the Go
 * and Rust implementations write. See {@link ConstMap} for how keys are hashed.
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class VerifiedConstMap {
  /**
   * The value returned for a key that is not in the map: all 64 bits set ({@code -1}, or
   * 2<sup>64</sup>-1 read as unsigned). A key mapped to this value cannot be told apart from a
   * missing key.
   */
  public static final long NOT_FOUND = ConstMaps.NOT_FOUND;

  private final ConstMaps.Params params;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final long[] data;
  private final long[] checks;

  private VerifiedConstMap(ConstMaps.Params params, long[] data, long[] checks) {
    this.params = params;
    this.seed = params.seed();
    this.segmentLength = params.segmentLength();
    this.segmentLengthMask = params.segmentLengthMask();
    this.segmentCountLength = params.segmentCountLength();
    this.data = data;
    this.checks = checks;
  }

  /**
   * Builds a map from string keys and their values: {@code keys.get(i)} maps to
   * {@code values[i]}. Keys must be distinct. Construction is deterministic.
   *
   * @param keys the keys, distinct
   * @param values the values, one per key
   * @return the map
   * @throws IllegalArgumentException if the lengths differ, if two keys are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  public static VerifiedConstMap build(List<String> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return buildFromHashes(ConstMaps.hashStrings(keys), values);
  }

  /**
   * Builds a map from byte-array keys and their values: {@code keys.get(i)} maps to
   * {@code values[i]}. Keys must be distinct. Construction is deterministic.
   *
   * @param keys the keys, distinct
   * @param values the values, one per key
   * @return the map
   * @throws IllegalArgumentException if the lengths differ, if two keys are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  public static VerifiedConstMap buildFromBytes(List<byte[]> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return buildFromHashes(ConstMaps.hashBytes(keys), values);
  }

  /**
   * Builds a map from the XXH64 hashes of the keys ({@link XxHash64#hash(byte[])}) and their
   * values. Neither array is modified.
   *
   * @param keyHashes the XXH64 hashes (seed 0) of the keys, distinct
   * @param values the values, one per key
   * @return the map
   * @throws IllegalArgumentException if the lengths differ, if two hashes are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  public static VerifiedConstMap buildFromHashes(long[] keyHashes, long[] values) {
    ConstMaps.checkLengths(keyHashes.length, values.length);
    if (keyHashes.length == 0) {
      return new VerifiedConstMap(ConstMaps.Params.EMPTY, new long[0], new long[0]);
    }
    ConstMaps.Peeled p = ConstMaps.peel(keyHashes);
    int n = p.params().arrayLength();
    long[] data = new long[n];
    long[] checks = new long[n];
    ConstMaps.assign(p, values, data, checks);
    return new VerifiedConstMap(p.params(), data, checks);
  }

  /**
   * Returns the value of a key whose XXH64 hash (seed 0) is given. Equivalent to the other
   * {@code get} methods on the key itself.
   *
   * @param keyHash the XXH64 hash of the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  public long getByHash(long keyHash) {
    if (data.length == 0) {
      return NOT_FOUND;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    if ((checks[h0] ^ checks[h1] ^ checks[h2]) != ConstMaps.fingerprint(hash)) {
      return NOT_FOUND;
    }
    return data[h0] ^ data[h1] ^ data[h2];
  }

  /**
   * Returns the value of a string key (hashed through its UTF-8 encoding).
   *
   * @param key the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  public long get(String key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns the value of a byte-array key.
   *
   * @param key the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  public long get(byte[] key) {
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
  public long get(byte[] key, int off, int len) {
    return getByHash(XxHash64.hash(key, off, len));
  }

  /**
   * Returns the value of the key made of the buffer's bytes from its position to its limit.
   * The buffer is not modified.
   *
   * @param key the key
   * @return the value, or {@link #NOT_FOUND} if the key is not in the map
   */
  public long get(ByteBuffer key) {
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
  public boolean containsKey(String key) {
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
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (data.length == 0) {
      Arrays.fill(dst, 0, n, NOT_FOUND);
      return;
    }
    final long[] d = data;
    final long[] c = checks;
    final int[] h = new int[3 * ConstMap.BLOCK];
    final long[] fp = new long[ConstMap.BLOCK];
    for (int start = 0; start < n; start += ConstMap.BLOCK) {
      int m = Math.min(ConstMap.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = h0;
        h[3 * j + 1] = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
        h[3 * j + 2] = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
        fp[j] = ConstMaps.fingerprint(hash);
      }
      for (int j = 0; j < m; j++) {
        int a = h[3 * j];
        int b = h[3 * j + 1];
        int e = h[3 * j + 2];
        long v = d[a] ^ d[b] ^ d[e];
        dst[start + j] = (c[a] ^ c[b] ^ c[e]) == fp[j] ? v : NOT_FOUND;
      }
    }
  }

  /**
   * Looks up many string keys at once, as {@link #getMany(List, long[])} does, into a new
   * array.
   *
   * @param keys the keys
   * @return the values, one per key, {@link #NOT_FOUND} for missing keys
   */
  public long[] getMany(List<String> keys) {
    long[] dst = new long[keys.size()];
    getMany(keys, dst);
    return dst;
  }

  /**
   * Returns the same map in the paired layout, as a copy.
   *
   * @return a {@link PairedVerifiedConstMap} giving the same answers
   */
  public PairedVerifiedConstMap paired() {
    long[] slots = new long[2 * data.length];
    for (int i = 0; i < data.length; i++) {
      slots[2 * i] = data[i];
      slots[2 * i + 1] = checks[i];
    }
    return PairedVerifiedConstMap.of(params, slots);
  }

  /**
   * Returns the number of positions in each of the map's two arrays: about 1.125 per key for
   * large maps, more for small ones.
   *
   * @return the array length
   */
  public int arrayLength() {
    return data.length;
  }

  /**
   * Returns the number of bytes written by {@link #serialize(ByteBuffer)}: a 32-byte header,
   * the two arrays, and an 8-byte checksum.
   *
   * @return the serialized size in bytes
   */
  public int serializedSize() {
    return ConstMaps.VMAP_HEADER + 16 * data.length + 8;
  }

  /**
   * Writes the map at the buffer's current position, in the {@code VMAP0001} format shared
   * with the Go, Rust and C implementations, and advances the position by
   * {@link #serializedSize()}. The buffer's byte order is ignored and left unchanged.
   *
   * @param out the destination
   * @throws java.nio.BufferOverflowException if fewer than {@link #serializedSize()} bytes
   *     remain
   * @throws java.nio.ReadOnlyBufferException if the buffer is read-only
   */
  public void serialize(ByteBuffer out) {
    ConstMaps.write(out, ConstMaps.MAGIC_VMAP, params, data.length, true, data, checks);
  }

  /**
   * Returns the serialized form of the map, as written by {@link #serialize(ByteBuffer)}.
   *
   * @return a new array of {@link #serializedSize()} bytes
   */
  public byte[] toByteArray() {
    byte[] bytes = new byte[serializedSize()];
    serialize(ByteBuffer.wrap(bytes));
    return bytes;
  }

  /**
   * Reads a serialized map ({@code VMAP0001}) starting at the buffer's position into a new
   * on-heap map, after validating its header and checksum. The buffer's position is not
   * changed.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return the map
   * @throws InvalidFilterException if the input is not a valid {@code VerifiedConstMap} or is
   *     corrupt
   */
  public static VerifiedConstMap load(ByteBuffer buffer) {
    ConstMaps.Header h = ConstMaps.read(buffer, ConstMaps.Kind.VERIFIED, 2);
    int n = h.params().arrayLength();
    return new VerifiedConstMap(h.params(), ConstMaps.readWords(buffer, h.start(), n),
        ConstMaps.readWords(buffer, h.start() + 8 * n, n));
  }

  /**
   * Reads a serialized map, as {@link #load(ByteBuffer)} does.
   *
   * @param bytes the serialized map
   * @return the map
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  public static VerifiedConstMap load(byte[] bytes) {
    return load(ByteBuffer.wrap(bytes));
  }

  @Override
  public String toString() {
    return "VerifiedConstMap{positions=" + data.length + ", bytes=" + serializedSize() + "}";
  }
}
