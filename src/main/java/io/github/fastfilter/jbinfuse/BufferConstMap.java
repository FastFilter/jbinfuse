package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** A view of a serialized {@link ConstMap}, queried in place. Created by {@link ConstMap#wrap}. */
final class BufferConstMap implements ConstMap {
  private final ByteBuffer serialized;
  private final ByteBuffer data;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final int arrayLength;

  private BufferConstMap(ByteBuffer buffer, ConstMaps.Header h) {
    ConstMaps.Params p = h.params();
    this.serialized = ConstMaps.slice(buffer, h.start(), h.totalBytes());
    this.data = ConstMaps.slice(buffer, h.arrayStart(), 8 * p.arrayLength());
    this.seed = p.seed();
    this.segmentLength = p.segmentLength();
    this.segmentLengthMask = p.segmentLengthMask();
    this.segmentCountLength = p.segmentCountLength();
    this.arrayLength = p.arrayLength();
  }

  static BufferConstMap wrap(ByteBuffer buffer) {
    return new BufferConstMap(buffer, ConstMaps.readHeader(buffer, ConstMaps.Kind.CONST, 1));
  }

  @Override
  public long getByHash(long keyHash) {
    if (arrayLength == 0) {
      return 0;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    final ByteBuffer d = data;
    return d.getLong(8 * h0) ^ d.getLong(8 * h1) ^ d.getLong(8 * h2);
  }

  @Override
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (arrayLength == 0) {
      Arrays.fill(dst, 0, n, 0);
      return;
    }
    final ByteBuffer d = data;
    final int[] h = new int[3 * ConstMaps.BLOCK];
    for (int start = 0; start < n; start += ConstMaps.BLOCK) {
      int m = Math.min(ConstMaps.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = 8 * h0;
        h[3 * j + 1] = 8 * ((h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask));
        h[3 * j + 2] = 8 * ((h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask));
      }
      for (int j = 0; j < m; j++) {
        dst[start + j] = d.getLong(h[3 * j]) ^ d.getLong(h[3 * j + 1]) ^ d.getLong(h[3 * j + 2]);
      }
    }
  }

  @Override
  public int arrayLength() {
    return arrayLength;
  }

  @Override
  public int serializedSize() {
    return serialized.capacity();
  }

  @Override
  public void serialize(ByteBuffer out) {
    ConstMaps.copy(serialized, out);
  }

  @Override
  public String toString() {
    return "ConstMapView{words=" + arrayLength + ", bytes=" + serializedSize() + "}";
  }
}
