package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;

/**
 * An immutable binary fuse filter (arity 3): an approximate set of 64-bit keys that answers
 * membership queries with no false negatives and a small false-positive probability (about
 * 2<sup>-8</sup> for {@link BinaryFuse8}, 2<sup>-16</sup> for {@link BinaryFuse16}).
 *
 * <p>There are two kinds of implementations, which always give identical answers:
 * <ul>
 *   <li>on-heap filters, {@link BinaryFuse8} and {@link BinaryFuse16}, built from keys with
 *       their {@code build} methods or copied from serialized bytes with {@link #load};</li>
 *   <li>views returned by {@link #wrap(ByteBuffer)}, which query serialized bytes in place
 *       (a heap buffer, a direct buffer or a {@link java.nio.MappedByteBuffer} of a file)
 *       without copying them. Views use almost no heap and open instantly; on-heap filters
 *       answer queries faster.</li>
 * </ul>
 *
 * <p>Byte-array keys are first hashed to 64 bits with {@link WyHash#hash(byte[])}; the
 * {@code contains(byte[])} family does the same, so {@code contains(bytes)} is exactly
 * {@code contains(WyHash.hash(bytes))}.
 *
 * <p>Filters are immutable and safe for concurrent queries. A view stays valid only as long
 * as the bytes of the underlying buffer are not modified.
 */
public sealed interface BinaryFuseFilter
    permits BinaryFuse8, BinaryFuse16, BufferBinaryFuse8, BufferBinaryFuse16 {

  /**
   * Tests whether a 64-bit key may be in the set.
   *
   * @param key the key
   * @return {@code true} if the key was added at construction (always) or, with a small
   *     probability, if it was not; {@code false} if it was definitely not added
   */
  boolean contains(long key);

  /**
   * Tests whether a byte-array key may be in the set. Equivalent to
   * {@code contains(WyHash.hash(key))}.
   *
   * @param key the key bytes
   * @return {@code false} if the key was definitely not added
   */
  default boolean contains(byte[] key) {
    return contains(WyHash.hash(key));
  }

  /**
   * Tests whether the key formed by {@code len} bytes of {@code key} starting at {@code off}
   * may be in the set. Equivalent to {@code contains(WyHash.hash(key, off, len))}.
   *
   * @param key the array holding the key bytes
   * @param off the index of the first key byte
   * @param len the key length in bytes
   * @return {@code false} if the key was definitely not added
   */
  default boolean contains(byte[] key, int off, int len) {
    return contains(WyHash.hash(key, off, len));
  }

  /**
   * Tests whether the key formed by the remaining bytes of a buffer may be in the set.
   * Equivalent to {@code contains(WyHash.hash(key))}. The buffer's position is not changed.
   *
   * @param key a buffer whose bytes from position to limit are the key
   * @return {@code false} if the key was definitely not added
   */
  default boolean contains(ByteBuffer key) {
    return contains(WyHash.hash(key));
  }

  /**
   * Returns the fingerprint size.
   *
   * @return 8 or 16
   */
  int fingerprintBits();

  /**
   * Returns the number of distinct 64-bit keys stored in the filter (duplicates in the input
   * are counted once).
   *
   * @return the number of keys
   */
  int keyCount();

  /**
   * Returns the number of bytes written by {@link #serialize(ByteBuffer)}: a 40-byte header
   * followed by the fingerprints.
   *
   * @return the serialized size in bytes
   */
  int serializedSize();

  /**
   * Writes the filter at the buffer's current position, in the versioned little-endian
   * format read by {@link #wrap} and {@link #load}, and advances the position by
   * {@link #serializedSize()}. The buffer's byte order is ignored and left unchanged.
   *
   * @param out the destination
   * @throws java.nio.BufferOverflowException if fewer than {@link #serializedSize()} bytes
   *     remain
   * @throws java.nio.ReadOnlyBufferException if the buffer is read-only
   */
  void serialize(ByteBuffer out);

  /**
   * Returns the serialized form of the filter.
   *
   * @return a new array of {@link #serializedSize()} bytes
   */
  default byte[] toByteArray() {
    byte[] bytes = new byte[serializedSize()];
    serialize(ByteBuffer.wrap(bytes));
    return bytes;
  }

  /**
   * Returns a filter that queries the serialized filter starting at the buffer's position
   * directly, without copying it. The buffer may be on the heap, direct or a
   * {@link java.nio.MappedByteBuffer}; its position, limit and byte order are not changed.
   *
   * <p>A view uses almost no heap and opens instantly, but queries are slower than with an
   * on-heap filter from {@link #load}, noticeably so for a memory-mapped file (several
   * nanoseconds per query in our measurements).
   *
   * <p>This method runs in constant time: it validates the header (magic bytes, format
   * version, variant, parameters and header checksum) and checks that the buffer is long
   * enough, but it does not checksum the fingerprints. Use {@link #load} for full validation.
   *
   * @param buffer a buffer holding a serialized filter at its position; bytes after the
   *     filter are ignored
   * @return a view backed by the buffer
   * @throws InvalidFilterException if the header is invalid or the buffer is too short
   */
  static BinaryFuseFilter wrap(ByteBuffer buffer) {
    Fuse.Header h = Fuse.readHeader(buffer);
    return h.bits() == 8 ? new BufferBinaryFuse8(buffer, h) : new BufferBinaryFuse16(buffer, h);
  }

  /**
   * Reads a serialized filter starting at the buffer's position into a new on-heap filter
   * ({@link BinaryFuse8} or {@link BinaryFuse16}), after full validation including the
   * fingerprint checksum. The buffer's position is not changed.
   *
   * @param buffer a buffer holding a serialized filter at its position
   * @return an on-heap copy of the filter
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  static BinaryFuseFilter load(ByteBuffer buffer) {
    Fuse.Header h = Fuse.readHeader(buffer);
    Fuse.verifyPayload(buffer, h);
    return h.bits() == 8 ? BinaryFuse8.read(buffer, h) : BinaryFuse16.read(buffer, h);
  }

  /**
   * Reads a serialized filter into a new on-heap filter, after full validation.
   *
   * @param bytes the serialized filter, as produced by {@link #toByteArray()}
   * @return an on-heap copy of the filter
   * @throws InvalidFilterException if the input is invalid or corrupt
   */
  static BinaryFuseFilter load(byte[] bytes) {
    return load(ByteBuffer.wrap(bytes));
  }
}
