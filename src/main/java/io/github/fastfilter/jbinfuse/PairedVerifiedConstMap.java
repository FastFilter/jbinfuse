package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A {@link VerifiedConstMap} with each value stored next to its check word, so that a lookup
 * touches three cache lines instead of six. Same answers, same size (about 18 bytes per key);
 * faster when most keys looked up are present, slower when most are missing (the verified
 * layout then reads only its check array, half the size of the map).
 *
 * <p>This is a Java implementation of the {@code PairedVerifiedConstMap} of
 * <a href="https://github.com/lemire/constmap">constmap</a> (Go). Its serialized form
 * ({@code PMAP0001}) is shared with constmap, rsconstmap (Rust) and fastconstmap (C and
 * Python), and for the same keys and values this class writes exactly the bytes that the Go
 * and Rust implementations write. See {@link ConstMap} for how keys are hashed.
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class PairedVerifiedConstMap {
  private final ConstMaps.Params params;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  /** The value for position i at slots[2i], its check word at slots[2i+1]. */
  private final long[] slots;

  private PairedVerifiedConstMap(ConstMaps.Params params, long[] slots) {
    this.params = params;
    this.seed = params.seed();
    this.segmentLength = params.segmentLength();
    this.segmentLengthMask = params.segmentLengthMask();
    this.segmentCountLength = params.segmentCountLength();
    this.slots = slots;
  }

  static PairedVerifiedConstMap of(ConstMaps.Params params, long[] slots) {
    return new PairedVerifiedConstMap(params, slots);
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
  public static PairedVerifiedConstMap build(List<String> keys, long[] values) {
    return VerifiedConstMap.build(keys, values).paired();
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
  public static PairedVerifiedConstMap buildFromBytes(List<byte[]> keys, long[] values) {
    return VerifiedConstMap.buildFromBytes(keys, values).paired();
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
  public static PairedVerifiedConstMap buildFromHashes(long[] keyHashes, long[] values) {
    return VerifiedConstMap.buildFromHashes(keyHashes, values).paired();
  }

  /**
   * Returns the value of a key whose XXH64 hash (seed 0) is given. Equivalent to the other
   * {@code get} methods on the key itself.
   *
   * @param keyHash the XXH64 hash of the key
   * @return the value, or {@link VerifiedConstMap#NOT_FOUND} if the key is not in the map
   */
  public long getByHash(long keyHash) {
    if (slots.length == 0) {
      return ConstMaps.NOT_FOUND;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    final long[] s = slots;
    int i0 = 2 * h0;
    int i1 = 2 * h1;
    int i2 = 2 * h2;
    if ((s[i0 + 1] ^ s[i1 + 1] ^ s[i2 + 1]) != ConstMaps.fingerprint(hash)) {
      return ConstMaps.NOT_FOUND;
    }
    return s[i0] ^ s[i1] ^ s[i2];
  }

  /**
   * Returns the value of a string key (hashed through its UTF-8 encoding).
   *
   * @param key the key
   * @return the value, or {@link VerifiedConstMap#NOT_FOUND} if the key is not in the map
   */
  public long get(String key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns the value of a byte-array key.
   *
   * @param key the key
   * @return the value, or {@link VerifiedConstMap#NOT_FOUND} if the key is not in the map
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
   * @return the value, or {@link VerifiedConstMap#NOT_FOUND} if the key is not in the map
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
   * @return the value, or {@link VerifiedConstMap#NOT_FOUND} if the key is not in the map
   */
  public long get(ByteBuffer key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns whether a string key is in the map, that is, whether {@link #get(String)} does not
   * return {@link VerifiedConstMap#NOT_FOUND}.
   *
   * @param key the key
   * @return true if the key is in the map (or, with probability about 2<sup>-64</sup>, a
   *     false positive), false if it is not or if its value is
   *     {@link VerifiedConstMap#NOT_FOUND}
   */
  public boolean containsKey(String key) {
    return get(key) != ConstMaps.NOT_FOUND;
  }

  /**
   * Looks up many string keys at once: {@code dst[i]} receives the value of
   * {@code keys.get(i)}, exactly as {@link #get(String)} would return it. Hashing every key
   * of a block before reading the array lets the processor overlap the memory accesses of
   * several lookups.
   *
   * @param keys the keys
   * @param dst where the values go; only the first {@code keys.size()} entries are written
   * @throws IndexOutOfBoundsException if {@code dst} is shorter than {@code keys}
   */
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (slots.length == 0) {
      Arrays.fill(dst, 0, n, ConstMaps.NOT_FOUND);
      return;
    }
    final long[] s = slots;
    final int[] h = new int[3 * ConstMap.BLOCK];
    final long[] fp = new long[ConstMap.BLOCK];
    for (int start = 0; start < n; start += ConstMap.BLOCK) {
      int m = Math.min(ConstMap.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = 2 * h0;
        h[3 * j + 1] = 2 * ((h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask));
        h[3 * j + 2] = 2 * ((h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask));
        fp[j] = ConstMaps.fingerprint(hash);
      }
      for (int j = 0; j < m; j++) {
        int a = h[3 * j];
        int b = h[3 * j + 1];
        int c = h[3 * j + 2];
        long v = s[a] ^ s[b] ^ s[c];
        dst[start + j] = (s[a + 1] ^ s[b + 1] ^ s[c + 1]) == fp[j] ? v : ConstMaps.NOT_FOUND;
      }
    }
  }

  /**
   * Looks up many string keys at once, as {@link #getMany(List, long[])} does, into a new
   * array.
   *
   * @param keys the keys
   * @return the values, one per key, {@link VerifiedConstMap#NOT_FOUND} for missing keys
   */
  public long[] getMany(List<String> keys) {
    long[] dst = new long[keys.size()];
    getMany(keys, dst);
    return dst;
  }

  /**
   * Returns the number of positions (value and check word pairs) in the map: about 1.125 per
   * key for large maps, more for small ones.
   *
   * @return the number of positions
   */
  public int arrayLength() {
    return slots.length / 2;
  }

  /**
   * Returns the number of bytes written by {@link #serialize(ByteBuffer)}: a 32-byte header,
   * the slots, and an 8-byte checksum.
   *
   * @return the serialized size in bytes
   */
  public int serializedSize() {
    return ConstMaps.VMAP_HEADER + 8 * slots.length + 8;
  }

  /**
   * Writes the map at the buffer's current position, in the {@code PMAP0001} format shared
   * with the Go, Rust and C implementations, and advances the position by
   * {@link #serializedSize()}. The buffer's byte order is ignored and left unchanged.
   *
   * @param out the destination
   * @throws java.nio.BufferOverflowException if fewer than {@link #serializedSize()} bytes
   *     remain
   * @throws java.nio.ReadOnlyBufferException if the buffer is read-only
   */
  public void serialize(ByteBuffer out) {
    ConstMaps.write(out, ConstMaps.MAGIC_PMAP, params, slots.length / 2, true, slots);
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
   * Reads a serialized map ({@code PMAP0001}) starting at the buffer's position into a new
   * on-heap map, after validating its header and checksum. The buffer's position is not
   * changed.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return the map
   * @throws InvalidFilterException if the input is not a valid {@code PairedVerifiedConstMap}
   *     or is corrupt
   */
  public static PairedVerifiedConstMap load(ByteBuffer buffer) {
    ConstMaps.Header h = ConstMaps.read(buffer, ConstMaps.Kind.PAIRED, 2);
    int n = h.params().arrayLength();
    return new PairedVerifiedConstMap(h.params(), ConstMaps.readWords(buffer, h.start(), 2 * n));
  }

  /**
   * Reads a serialized map, as {@link #load(ByteBuffer)} does.
   *
   * @param bytes the serialized map
   * @return the map
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  public static PairedVerifiedConstMap load(byte[] bytes) {
    return load(ByteBuffer.wrap(bytes));
  }

  @Override
  public String toString() {
    return "PairedVerifiedConstMap{positions=" + arrayLength() + ", bytes=" + serializedSize()
        + "}";
  }
}
