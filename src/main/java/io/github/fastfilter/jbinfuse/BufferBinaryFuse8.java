package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;

/** A view of a serialized 8-bit filter, queried in place. Created by {@link BinaryFuseFilter#wrap}. */
final class BufferBinaryFuse8 implements BinaryFuseFilter {
  private final ByteBuffer serialized;
  private final ByteBuffer fingerprints;
  private final long seed;
  private final int keyCount;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final boolean empty;

  BufferBinaryFuse8(ByteBuffer buf, Fuse.Header h) {
    int start = buf.position();
    this.serialized = buf.slice(start, h.totalBytes());
    this.fingerprints = buf.slice(start + Fuse.HEADER_SIZE, h.payloadBytes());
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
    return (byte) (hash ^ (hash >>> 32) ^ fp.get(h0) ^ fp.get(h1) ^ fp.get(h2)) == 0;
  }

  @Override
  public int fingerprintBits() {
    return 8;
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
    return "BinaryFuse8View{keys=" + keyCount + ", bytes=" + serializedSize() + "}";
  }
}
