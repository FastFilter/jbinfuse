package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Collection;

/**
 * An on-heap binary fuse filter with 16-bit fingerprints: about 18 bits per key for large
 * sets and a false-positive probability of about 2<sup>-16</sup> (0.0015%).
 *
 * <p>Instances are immutable and thread-safe.
 */
public final class BinaryFuse16 implements BinaryFuseFilter {
  private final long seed;
  private final int keyCount;
  private final Fuse.Layout layout;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final short[] fingerprints;

  private BinaryFuse16(long seed, int keyCount, Fuse.Layout layout, short[] fingerprints) {
    this.seed = seed;
    this.keyCount = keyCount;
    this.layout = layout;
    this.segmentLength = layout.segmentLength();
    this.segmentLengthMask = layout.segmentLengthMask();
    this.segmentCountLength = layout.segmentCountLength();
    this.fingerprints = fingerprints;
  }

  /**
   * Builds a filter containing the given 64-bit keys. Duplicate keys are allowed. The array
   * is not modified. Construction is deterministic: the same keys always give the same
   * filter.
   *
   * @param keys the keys
   * @return the filter
   * @throws IllegalArgumentException if there are too many keys for one filter
   */
  public static BinaryFuse16 build(long[] keys) {
    return build(keys, keys.length);
  }

  /**
   * Builds a filter containing the first {@code length} keys of the array, for example when
   * the array was filled only partially. Otherwise identical to {@link #build(long[])}: the
   * array is not modified and duplicate keys are allowed.
   *
   * @param keys the array holding the keys
   * @param length the number of keys, from index 0
   * @return the filter
   * @throws IndexOutOfBoundsException if {@code length} is negative or larger than the array
   * @throws IllegalArgumentException if there are too many keys for one filter
   */
  public static BinaryFuse16 build(long[] keys, int length) {
    java.util.Objects.checkFromIndexSize(0, length, keys.length);
    Fuse.Layout layout = Fuse.Layout.forSize(length, 16);
    short[] fp = new short[layout.arrayLength()];
    if (length == 0) {
      return new BinaryFuse16(0, 0, layout, fp);
    }
    Fuse.Peeled p = Fuse.peel(keys, length, layout);
    final long[] order = p.reverseOrder();
    final byte[] which = p.reverseH();
    final int len = layout.segmentLength();
    final int mask = layout.segmentLengthMask();
    final long scl = layout.segmentCountLength();
    for (int i = p.size() - 1; i >= 0; i--) {
      long hash = order[i];
      int h0 = (int) Math.unsignedMultiplyHigh(hash, scl);
      int h1 = (h0 + len) ^ ((int) (hash >>> 18) & mask);
      int h2 = (h0 + 2 * len) ^ ((int) hash & mask);
      short f = (short) (hash ^ (hash >>> 32));
      switch (which[i]) {
        case 0 -> fp[h0] = (short) (f ^ fp[h1] ^ fp[h2]);
        case 1 -> fp[h1] = (short) (f ^ fp[h0] ^ fp[h2]);
        default -> fp[h2] = (short) (f ^ fp[h0] ^ fp[h1]);
      }
    }
    return new BinaryFuse16(p.seed(), p.size(), layout, fp);
  }

  /**
   * Builds a filter containing the given byte-array keys, each hashed to 64 bits with
   * {@link WyHash#hash(byte[])}. Duplicate keys are allowed.
   *
   * @param keys the keys
   * @return the filter
   * @throws IllegalArgumentException if there are too many keys for one filter
   */
  public static BinaryFuse16 buildFromBytes(Collection<byte[]> keys) {
    return build(Fuse.hashAll(keys));
  }

  static BinaryFuse16 read(ByteBuffer buf, Fuse.Header h) {
    short[] fp = new short[h.layout().arrayLength()];
    buf.duplicate().position(buf.position() + Fuse.HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        .asShortBuffer().get(fp);
    return new BinaryFuse16(h.seed(), h.keyCount(), h.layout(), fp);
  }

  @Override
  public boolean contains(long key) {
    long hash = Fuse.hash(key, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    short[] fp = fingerprints;
    if (fp.length == 0) {
      return false;
    }
    return (short) (hash ^ (hash >>> 32) ^ fp[h0] ^ fp[h1] ^ fp[h2]) == 0;
  }

  @Override
  public int fingerprintBits() {
    return 16;
  }

  @Override
  public int keyCount() {
    return keyCount;
  }

  @Override
  public int serializedSize() {
    return Fuse.HEADER_SIZE + 2 * fingerprints.length;
  }

  @Override
  public void serialize(ByteBuffer out) {
    Fuse.checkSpace(out, serializedSize());
    out.duplicate().position(out.position() + Fuse.HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        .asShortBuffer().put(fingerprints);
    Fuse.finishWrite(out, 16, seed, keyCount, layout);
  }

  @Override
  public String toString() {
    return "BinaryFuse16{keys=" + keyCount + ", bytes=" + serializedSize() + "}";
  }
}
