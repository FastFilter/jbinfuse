package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** An on-heap {@link VerifiedConstMap}. */
final class HeapVerifiedConstMap implements VerifiedConstMap {
  private final ConstMaps.Params params;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  private final long[] data;
  private final long[] checks;

  private HeapVerifiedConstMap(ConstMaps.Params params, long[] data, long[] checks) {
    this.params = params;
    this.seed = params.seed();
    this.segmentLength = params.segmentLength();
    this.segmentLengthMask = params.segmentLengthMask();
    this.segmentCountLength = params.segmentCountLength();
    this.data = data;
    this.checks = checks;
  }

  static HeapVerifiedConstMap build(long[] keyHashes, long[] values) {
    if (keyHashes.length == 0) {
      return new HeapVerifiedConstMap(ConstMaps.Params.EMPTY, new long[0], new long[0]);
    }
    ConstMaps.Peeled p = ConstMaps.peel(keyHashes);
    int n = p.params().arrayLength();
    long[] data = new long[n];
    long[] checks = new long[n];
    ConstMaps.assign(p, values, data, checks);
    return new HeapVerifiedConstMap(p.params(), data, checks);
  }

  static HeapVerifiedConstMap read(ByteBuffer buffer) {
    ConstMaps.Header h = ConstMaps.read(buffer, ConstMaps.Kind.VERIFIED, 2);
    int n = h.params().arrayLength();
    return new HeapVerifiedConstMap(h.params(), ConstMaps.readWords(buffer, h.arrayStart(), n),
        ConstMaps.readWords(buffer, h.arrayStart() + 8 * n, n));
  }

  @Override
  public long getByHash(long keyHash) {
    if (data.length == 0) {
      return NOT_FOUND;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    if ((checks[h0] ^ checks[h1] ^ checks[h2]) != ConstMaps.fingerprint(hash)) {
      return NOT_FOUND;
    }
    return data[h0] ^ data[h1] ^ data[h2];
  }

  @Override
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (data.length == 0) {
      Arrays.fill(dst, 0, n, NOT_FOUND);
      return;
    }
    final long[] d = data;
    final long[] c = checks;
    final int[] h = new int[3 * ConstMaps.BLOCK];
    final long[] fp = new long[ConstMaps.BLOCK];
    for (int start = 0; start < n; start += ConstMaps.BLOCK) {
      int m = Math.min(ConstMaps.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = h0;
        h[3 * j + 1] = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
        h[3 * j + 2] = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
        fp[j] = ConstMaps.fingerprint(hash);
      }
      for (int j = 0; j < m; j++) {
        int a = h[3 * j];
        int b = h[3 * j + 1];
        int e = h[3 * j + 2];
        long v = d[a] ^ d[b] ^ d[e];
        dst[start + j] = (c[a] ^ c[b] ^ c[e]) == fp[j] ? v : NOT_FOUND;
      }
    }
  }

  @Override
  public PairedVerifiedConstMap paired() {
    long[] slots = new long[2 * data.length];
    for (int i = 0; i < data.length; i++) {
      slots[2 * i] = data[i];
      slots[2 * i + 1] = checks[i];
    }
    return HeapPairedVerifiedConstMap.of(params, slots);
  }

  @Override
  public int arrayLength() {
    return data.length;
  }

  @Override
  public int serializedSize() {
    return ConstMaps.VMAP_HEADER + 16 * data.length + 8;
  }

  @Override
  public void serialize(ByteBuffer out) {
    ConstMaps.write(out, ConstMaps.MAGIC_VMAP, params, data.length, true, data, checks);
  }

  @Override
  public String toString() {
    return "VerifiedConstMap{positions=" + data.length + ", bytes=" + serializedSize() + "}";
  }
}
