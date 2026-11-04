package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** A view of a serialized 16-bit filter, queried in place. Created by {@link BinaryFuseFilter#wrap}. */
final class BufferBinaryFuse16 implements BinaryFuseFilter {
  private final ByteBuffer serialized;
  private final ByteBuffer fingerprints;
  private final long seed;
  private final int keyCount;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final boolean empty;

  BufferBinaryFuse16(ByteBuffer buf, Fuse.Header h) {
    int start = buf.position();
    this.serialized = buf.slice(start, h.totalBytes());
    this.fingerprints = buf.slice(start + Fuse.HEADER_SIZE, h.payloadBytes())
        .order(ByteOrder.LITTLE_ENDIAN);
    this.seed = h.seed();
    this.keyCount = h.keyCount();
    this.segmentLength = h.layout().segmentLength();
    this.segmentLengthMask = h.layout().segmentLengthMask();
    this.segmentCountLength = h.layout().segmentCountLength();
    this.empty = h.layout().arrayLength() == 0;
  }

  @Override
  public boolean contains(long key) {
    long hash = Fuse.hash(key, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    if (empty) {
      return false;
    }
    ByteBuffer fp = fingerprints;
    return (short) (hash ^ (hash >>> 32) ^ fp.getShort(2 * h0) ^ fp.getShort(2 * h1)
        ^ fp.getShort(2 * h2)) == 0;
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
    return serialized.capacity();
  }

  @Override
  public void serialize(ByteBuffer out) {
    out.put(serialized.duplicate());
  }

  @Override
  public String toString() {
    return "BinaryFuse16View{keys=" + keyCount + ", bytes=" + serializedSize() + "}";
  }
}
