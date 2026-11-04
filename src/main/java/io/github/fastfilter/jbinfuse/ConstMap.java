package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;

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
 * built by any of them loads in the others. For the same keys and values, this class writes
 * exactly the bytes that the Go and Rust implementations write.
 *
 * <p>String keys are hashed through their UTF-8 encoding, so {@code get("abc")} and
 * {@code get("abc".getBytes(UTF_8))} are the same lookup. Values are 64-bit words; read them as
 * unsigned if you need values above {@link Long#MAX_VALUE}.
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class ConstMap {
  private final ConstMaps.Params params;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final long[] data;

  private ConstMap(ConstMaps.Params params, long[] data) {
    this.params = params;
    this.seed = params.seed();
    this.segmentLength = params.segmentLength();
    this.segmentLengthMask = params.segmentLengthMask();
    this.segmentCountLength = params.segmentCountLength();
    this.data = data;
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
  public static ConstMap build(List<String> keys, long[] values) {
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
  public static ConstMap buildFromBytes(List<byte[]> keys, long[] values) {
    ConstMaps.checkLengths(keys.size(), values.length);
    return buildFromHashes(ConstMaps.hashBytes(keys), values);
  }

  /**
   * Builds a map from the XXH64 hashes of the keys ({@link XxHash64#hash(byte[])}) and their
   * values, for callers that hash keys as they stream them. Neither array is modified.
   *
   * @param keyHashes the XXH64 hashes (seed 0) of the keys, distinct
   * @param values the values, one per key
   * @return the map
   * @throws IllegalArgumentException if the lengths differ, if two hashes are equal (detected
   *     with high probability), or if there are too many keys for one map
   */
  public static ConstMap buildFromHashes(long[] keyHashes, long[] values) {
    ConstMaps.checkLengths(keyHashes.length, values.length);
    if (keyHashes.length == 0) {
      return new ConstMap(ConstMaps.Params.EMPTY, new long[0]);
    }
    ConstMaps.Peeled p = ConstMaps.peel(keyHashes);
    long[] data = new long[p.params().arrayLength()];
    ConstMaps.assign(p, values, data, null);
    return new ConstMap(p.params(), data);
  }

  /**
   * Returns the value of a key whose XXH64 hash (seed 0) is given. Equivalent to the other
   * {@code get} methods on the key itself.
   *
   * @param keyHash the XXH64 hash of the key
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  public long getByHash(long keyHash) {
    if (data.length == 0) {
      return 0;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    return data[h0] ^ data[h1] ^ data[h2];
  }

  /**
   * Returns the value of a string key (hashed through its UTF-8 encoding).
   *
   * @param key the key
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  public long get(String key) {
    return getByHash(XxHash64.hash(key));
  }

  /**
   * Returns the value of a byte-array key.
   *
   * @param key the key
   * @return the value if the key is in the map, an arbitrary value otherwise
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
   * @return the value if the key is in the map, an arbitrary value otherwise
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
   * @return the value if the key is in the map, an arbitrary value otherwise
   */
  public long get(ByteBuffer key) {
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
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (data.length == 0) {
      java.util.Arrays.fill(dst, 0, n, 0);
      return;
    }
    final long[] d = data;
    final int[] h = new int[3 * BLOCK];
    for (int start = 0; start < n; start += BLOCK) {
      int m = Math.min(BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = h0;
        h[3 * j + 1] = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
        h[3 * j + 2] = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
      }
      for (int j = 0; j < m; j++) {
        dst[start + j] = d[h[3 * j]] ^ d[h[3 * j + 1]] ^ d[h[3 * j + 2]];
      }
    }
  }

  /** Keys per block in {@link #getMany}. */
  static final int BLOCK = 8;

  /**
   * Looks up many string keys at once, as {@link #getMany(List, long[])} does, into a new
   * array.
   *
   * @param keys the keys
   * @return the values, one per key
   */
  public long[] getMany(List<String> keys) {
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
  public int arrayLength() {
    return data.length;
  }

  /**
   * Returns the number of bytes written by {@link #serialize(ByteBuffer)}: a 28-byte header,
   * the array, and an 8-byte checksum.
   *
   * @return the serialized size in bytes
   */
  public int serializedSize() {
    return ConstMaps.CMAP_HEADER + 8 * data.length + 8;
  }

  /**
   * Writes the map at the buffer's current position, in the {@code CMAP0001} format shared
   * with the Go, Rust and C implementations, and advances the position by
   * {@link #serializedSize()}. The buffer's byte order is ignored and left unchanged.
   *
   * @param out the destination
   * @throws java.nio.BufferOverflowException if fewer than {@link #serializedSize()} bytes
   *     remain
   * @throws java.nio.ReadOnlyBufferException if the buffer is read-only
   */
  public void serialize(ByteBuffer out) {
    ConstMaps.write(out, ConstMaps.MAGIC_CMAP, params, data.length, false, data);
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
   * Reads a serialized map starting at the buffer's position into a new on-heap map, after
   * validating its header and checksum. Accepts both the {@code CMAP0001} format (Go, Rust,
   * this class) and fastconstmap's {@code CMAP0003}, which adds a key count that is ignored.
   * The buffer's position is not changed.
   *
   * @param buffer a buffer holding a serialized map at its position
   * @return the map
   * @throws InvalidFilterException if the input is not a valid {@code ConstMap} (including a
   *     {@code VerifiedConstMap} or {@code PairedVerifiedConstMap}, or a file from
   *     fastconstmap 0.9 or earlier, which used another hash), or is corrupt
   */
  public static ConstMap load(ByteBuffer buffer) {
    ConstMaps.Header h = ConstMaps.read(buffer, ConstMaps.Kind.CONST, 1);
    int n = h.params().arrayLength();
    return new ConstMap(h.params(), ConstMaps.readWords(buffer, h.start(), n));
  }

  /**
   * Reads a serialized map, as {@link #load(ByteBuffer)} does.
   *
   * @param bytes the serialized map
   * @return the map
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  public static ConstMap load(byte[] bytes) {
    return load(ByteBuffer.wrap(bytes));
  }

  @Override
  public String toString() {
    return "ConstMap{words=" + data.length + ", bytes=" + serializedSize() + "}";
  }
}
