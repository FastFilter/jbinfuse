package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** An on-heap {@link PairedVerifiedConstMap}. */
final class HeapPairedVerifiedConstMap implements PairedVerifiedConstMap {
  private final ConstMaps.Params params;
  private final long seed;
  private final int segmentLength;
  private final int segmentLengthMask;
  private final long segmentCountLength;
  /** The value for position i at slots[2i], its check word at slots[2i+1]. */
  private final long[] slots;

  private HeapPairedVerifiedConstMap(ConstMaps.Params params, long[] slots) {
    this.params = params;
    this.seed = params.seed();
    this.segmentLength = params.segmentLength();
    this.segmentLengthMask = params.segmentLengthMask();
    this.segmentCountLength = params.segmentCountLength();
    this.slots = slots;
  }

  static HeapPairedVerifiedConstMap of(ConstMaps.Params params, long[] slots) {
    return new HeapPairedVerifiedConstMap(params, slots);
  }

  static HeapPairedVerifiedConstMap read(ByteBuffer buffer) {
    ConstMaps.Header h = ConstMaps.read(buffer, ConstMaps.Kind.PAIRED, 2);
    int n = h.params().arrayLength();
    return new HeapPairedVerifiedConstMap(h.params(),
        ConstMaps.readWords(buffer, h.arrayStart(), 2 * n));
  }

  @Override
  public long getByHash(long keyHash) {
    if (slots.length == 0) {
      return ConstMaps.NOT_FOUND;
    }
    long hash = ConstMaps.mixsplit(keyHash, seed);
    int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
    int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask);
    int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask);
    final long[] s = slots;
    int i0 = 2 * h0;
    int i1 = 2 * h1;
    int i2 = 2 * h2;
    if ((s[i0 + 1] ^ s[i1 + 1] ^ s[i2 + 1]) != ConstMaps.fingerprint(hash)) {
      return ConstMaps.NOT_FOUND;
    }
    return s[i0] ^ s[i1] ^ s[i2];
  }

  @Override
  public void getMany(List<String> keys, long[] dst) {
    int n = keys.size();
    Objects.checkFromIndexSize(0, n, dst.length);
    if (slots.length == 0) {
      Arrays.fill(dst, 0, n, ConstMaps.NOT_FOUND);
      return;
    }
    final long[] s = slots;
    final int[] h = new int[3 * ConstMaps.BLOCK];
    final long[] fp = new long[ConstMaps.BLOCK];
    for (int start = 0; start < n; start += ConstMaps.BLOCK) {
      int m = Math.min(ConstMaps.BLOCK, n - start);
      for (int j = 0; j < m; j++) {
        long hash = ConstMaps.mixsplit(XxHash64.hash(keys.get(start + j)), seed);
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        h[3 * j] = 2 * h0;
        h[3 * j + 1] = 2 * ((h0 + segmentLength) ^ ((int) (hash >>> 18) & segmentLengthMask));
        h[3 * j + 2] = 2 * ((h0 + 2 * segmentLength) ^ ((int) hash & segmentLengthMask));
        fp[j] = ConstMaps.fingerprint(hash);
      }
      for (int j = 0; j < m; j++) {
        int a = h[3 * j];
        int b = h[3 * j + 1];
        int c = h[3 * j + 2];
        long v = s[a] ^ s[b] ^ s[c];
        dst[start + j] = (s[a + 1] ^ s[b + 1] ^ s[c + 1]) == fp[j] ? v : ConstMaps.NOT_FOUND;
      }
    }
  }

  @Override
  public int arrayLength() {
    return slots.length / 2;
  }

  @Override
  public int serializedSize() {
    return ConstMaps.VMAP_HEADER + 8 * slots.length + 8;
  }

  @Override
  public void serialize(ByteBuffer out) {
    ConstMaps.write(out, ConstMaps.MAGIC_PMAP, params, slots.length / 2, true, slots);
  }

  @Override
  public String toString() {
    return "PairedVerifiedConstMap{positions=" + arrayLength() + ", bytes=" + serializedSize()
        + "}";
  }
}
