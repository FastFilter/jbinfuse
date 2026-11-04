package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** An on-heap {@link ConstMap}. */
final class HeapConstMap implements ConstMap {
  private final ConstMaps.Params params;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final long[] data;

  private HeapConstMap(ConstMaps.Params params, long[] data) {
    this.params = params;
    this.seed = params.seed();
    this.segmentLength = params.segmentLength();
    this.segmentLengthMask = params.segmentLengthMask();
    this.segmentCountLength = params.segmentCountLength();
    this.data = data;
  }

  static HeapConstMap build(long[] keyHashes, long[] values) {
    if (keyHashes.length == 0) {
      return new HeapConstMap(ConstMaps.Params.EMPTY, new long[0]);
    }
    ConstMaps.Peeled p = ConstMaps.peel(keyHashes);
    long[] data = new long[p.params().arrayLength()];
    ConstMaps.assign(p, values, data, null);
    return new HeapConstMap(p.params(), data);
  }

  static HeapConstMap read(ByteBuffer buffer) {
    ConstMaps.Header h = ConstMaps.read(buffer, ConstMaps.Kind.CONST, 1);
    int n = h.params().arrayLength();
    return new HeapConstMap(h.params(), ConstMaps.readWords(buffer, h.arrayStart(), n));
  }

  @Override
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

  @Override
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (data.length == 0) {
      Arrays.fill(dst, 0, n, 0);
      return;
    }
    final long[] d = data;
    final int[] h = new int[3 * ConstMaps.BLOCK];
    for (int start = 0; start < n; start += ConstMaps.BLOCK) {
      int m = Math.min(ConstMaps.BLOCK, n - start);
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

  @Override
  public int arrayLength() {
    return data.length;
  }

  @Override
  public int serializedSize() {
    return ConstMaps.CMAP_HEADER + 8 * data.length + 8;
  }

  @Override
  public void serialize(ByteBuffer out) {
    ConstMaps.write(out, ConstMaps.MAGIC_CMAP, params, data.length, false, data);
  }

  @Override
  public String toString() {
    return "ConstMap{words=" + data.length + ", bytes=" + serializedSize() + "}";
  }
}
