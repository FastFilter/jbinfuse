package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A view of a serialized {@link PairedVerifiedConstMap}, queried in place. Created by
 * {@link PairedVerifiedConstMap#wrap}.
 */
final class BufferPairedVerifiedConstMap implements PairedVerifiedConstMap {
  private final ByteBuffer serialized;
  /** The value for position i at byte 16i, its check word at byte 16i + 8. */
  private final ByteBuffer slots;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final int arrayLength;

  private BufferPairedVerifiedConstMap(ByteBuffer buffer, ConstMaps.Header h) {
    ConstMaps.Params p = h.params();
    this.serialized = ConstMaps.slice(buffer, h.start(), h.totalBytes());
    this.slots = ConstMaps.slice(buffer, h.arrayStart(), 16 * p.arrayLength());
    this.seed = p.seed();
    this.segmentLength = p.segmentLength();
    this.segmentLengthMask = p.segmentLengthMask();
    this.segmentCountLength = p.segmentCountLength();
    this.arrayLength = p.arrayLength();
  }

  static BufferPairedVerifiedConstMap wrap(ByteBuffer buffer) {
    return new BufferPairedVerifiedConstMap(buffer,
        ConstMaps.readHeader(buffer, ConstMaps.Kind.PAIRED, 2));
  }

  @Override
  public long getByHash(long keyHash) {
    if (arrayLength == 0) {
      return ConstMaps.NOT_FOUND;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    final ByteBuffer s = slots;
    int a = 16 * h0;
    int b = 16 * h1;
    int c = 16 * h2;
    if ((s.getLong(a + 8) ^ s.getLong(b + 8) ^ s.getLong(c + 8))
        != ConstMaps.fingerprint(hash)) {
      return ConstMaps.NOT_FOUND;
    }
    return s.getLong(a) ^ s.getLong(b) ^ s.getLong(c);
  }

  @Override
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (arrayLength == 0) {
      Arrays.fill(dst, 0, n, ConstMaps.NOT_FOUND);
      return;
    }
    final ByteBuffer s = slots;
    final int[] h = new int[3 * ConstMaps.BLOCK];
    final long[] fp = new long[ConstMaps.BLOCK];
    for (int start = 0; start < n; start += ConstMaps.BLOCK) {
      int m = Math.min(ConstMaps.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = 16 * h0;
        h[3 * j + 1] = 16 * ((h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask));
        h[3 * j + 2] = 16 * ((h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask));
        fp[j] = ConstMaps.fingerprint(hash);
      }
      for (int j = 0; j < m; j++) {
        int a = h[3 * j];
        int b = h[3 * j + 1];
        int c = h[3 * j + 2];
        long v = s.getLong(a) ^ s.getLong(b) ^ s.getLong(c);
        dst[start + j] = (s.getLong(a + 8) ^ s.getLong(b + 8) ^ s.getLong(c + 8)) == fp[j]
            ? v : ConstMaps.NOT_FOUND;
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
    return "PairedVerifiedConstMapView{positions=" + arrayLength + ", bytes=" + serializedSize()
        + "}";
  }
}
