package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A view of a serialized {@link VerifiedConstMap}, queried in place. Created by
 * {@link VerifiedConstMap#wrap}.
 */
final class BufferVerifiedConstMap implements VerifiedConstMap {
  private final ConstMaps.Params params;
  private final ByteBuffer serialized;
  private final ByteBuffer data;
  private final ByteBuffer checks;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final int arrayLength;

  private BufferVerifiedConstMap(ByteBuffer buffer, ConstMaps.Header h) {
    ConstMaps.Params p = h.params();
    int n = p.arrayLength();
    this.params = p;
    this.serialized = ConstMaps.slice(buffer, h.start(), h.totalBytes());
    this.data = ConstMaps.slice(buffer, h.arrayStart(), 8 * n);
    this.checks = ConstMaps.slice(buffer, h.arrayStart() + 8 * n, 8 * n);
    this.seed = p.seed();
    this.segmentLength = p.segmentLength();
    this.segmentLengthMask = p.segmentLengthMask();
    this.segmentCountLength = p.segmentCountLength();
    this.arrayLength = n;
  }

  static BufferVerifiedConstMap wrap(ByteBuffer buffer) {
    return new BufferVerifiedConstMap(buffer,
        ConstMaps.readHeader(buffer, ConstMaps.Kind.VERIFIED, 2));
  }

  @Override
  public long getByHash(long keyHash) {
    if (arrayLength == 0) {
      return NOT_FOUND;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    final ByteBuffer c = checks;
    int a = 8 * h0;
    int b = 8 * h1;
    int e = 8 * h2;
    if ((c.getLong(a) ^ c.getLong(b) ^ c.getLong(e)) != ConstMaps.fingerprint(hash)) {
      return NOT_FOUND;
    }
    final ByteBuffer d = data;
    return d.getLong(a) ^ d.getLong(b) ^ d.getLong(e);
  }

  @Override
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (arrayLength == 0) {
      Arrays.fill(dst, 0, n, NOT_FOUND);
      return;
    }
    final ByteBuffer d = data;
    final ByteBuffer c = checks;
    final int[] h = new int[3 * ConstMaps.BLOCK];
    final long[] fp = new long[ConstMaps.BLOCK];
    for (int start = 0; start < n; start += ConstMaps.BLOCK) {
      int m = Math.min(ConstMaps.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = 8 * h0;
        h[3 * j + 1] = 8 * ((h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask));
        h[3 * j + 2] = 8 * ((h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask));
        fp[j] = ConstMaps.fingerprint(hash);
      }
      for (int j = 0; j < m; j++) {
        int a = h[3 * j];
        int b = h[3 * j + 1];
        int e = h[3 * j + 2];
        long v = d.getLong(a) ^ d.getLong(b) ^ d.getLong(e);
        dst[start + j] = (c.getLong(a) ^ c.getLong(b) ^ c.getLong(e)) == fp[j] ? v : NOT_FOUND;
      }
    }
  }

  @Override
  public PairedVerifiedConstMap paired() {
    long[] slots = new long[2 * arrayLength];
    for (int i = 0; i < arrayLength; i++) {
      slots[2 * i] = data.getLong(8 * i);
      slots[2 * i + 1] = checks.getLong(8 * i);
    }
    return HeapPairedVerifiedConstMap.of(params, slots);
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
    return "VerifiedConstMapView{positions=" + arrayLength + ", bytes=" + serializedSize() + "}";
  }
}
