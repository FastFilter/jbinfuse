package io.github.fastfilter.jbinfuse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BinaryFuseFilterTest {

  static long[] randomKeys(int n, long seed) {
    SplittableRandom r = new SplittableRandom(seed);
    long[] keys = new long[n];
    for (int i = 0; i < n; i++) {
      keys[i] = r.nextLong();
    }
    return keys;
  }

  static BinaryFuseFilter build(int bits, long[] keys) {
    return bits == 8 ? BinaryFuse8.build(keys) : BinaryFuse16.build(keys);
  }

  static BinaryFuseFilter buildFromBytes(int bits, List<byte[]> keys) {
    return bits == 8 ? BinaryFuse8.buildFromBytes(keys) : BinaryFuse16.buildFromBytes(keys);
  }

  static void assertAllPresent(BinaryFuseFilter f, long[] keys) {
    for (long k : keys) {
      if (!f.contains(k)) {
        throw new AssertionError("false negative for key " + k + " in " + f);
      }
    }
  }

  /** Counts positives among random queries (almost surely not in the set). */
  static long countPositives(BinaryFuseFilter f, int queries, long seed) {
    SplittableRandom r = new SplittableRandom(seed);
    long fp = 0;
    for (int i = 0; i < queries; i++) {
      if (f.contains(r.nextLong())) {
        fp++;
      }
    }
    return fp;
  }

  /** Asserts that a count is within z standard deviations of a binomial expectation. */
  static void assertBinomial(long count, long trials, double p, double z, String what) {
    double mean = trials * p;
    double sd = Math.sqrt(trials * p * (1 - p));
    assertTrue(Math.abs(count - mean) <= z * sd + 1,
        what + ": " + count + " positives in " + trials + " trials, expected " + mean
            + " +- " + z * sd);
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void noFalseNegativesSmallSizes(int bits) {
    for (int n = 0; n <= 3000; n++) {
      long[] keys = randomKeys(n, n * 31L + bits);
      BinaryFuseFilter f = build(bits, keys);
      assertEquals(n, f.keyCount());
      assertEquals(bits, f.fingerprintBits());
      assertAllPresent(f, keys);
      BinaryFuseFilter view = BinaryFuseFilter.wrap(ByteBuffer.wrap(f.toByteArray()));
      assertAllPresent(view, keys);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void noFalseNegativesLargeSizes(int bits) {
    for (int n : new int[] {10_000, 100_000, 1_000_000, 3_000_000}) {
      long[] keys = randomKeys(n, n + bits);
      BinaryFuseFilter f = build(bits, keys);
      assertAllPresent(f, keys);
      assertEquals(n, f.keyCount());
      double bitsPerKey = 8.0 * f.serializedSize() / n;
      if (n >= 1_000_000) {
        assertTrue(bitsPerKey < 1.14 * bits, "bits/key " + bitsPerKey);
      }
    }
  }

  @Test
  void emptyFilterContainsNothing() {
    for (int bits : new int[] {8, 16}) {
      BinaryFuseFilter f = build(bits, new long[0]);
      assertEquals(0, f.keyCount());
      assertEquals(0, countPositives(f, 100_000, 1));
      BinaryFuseFilter view = BinaryFuseFilter.wrap(ByteBuffer.wrap(f.toByteArray()));
      assertEquals(0, countPositives(view, 100_000, 1));
      assertEquals(Fuse.HEADER_SIZE, f.serializedSize());
      assertFalse(f.contains(new byte[0]));
    }
  }

  @Test
  void singleKey() {
    for (int bits : new int[] {8, 16}) {
      for (long key : new long[] {0, 1, -1, Long.MIN_VALUE, 123456789}) {
        BinaryFuseFilter f = build(bits, new long[] {key});
        assertTrue(f.contains(key));
        assertEquals(1, f.keyCount());
      }
    }
  }

  @Test
  void falsePositiveRate8() {
    BinaryFuseFilter f = BinaryFuse8.build(randomKeys(1_000_000, 42));
    int queries = 2_000_000;
    long fp = countPositives(f, queries, 4242);
    assertBinomial(fp, queries, 1.0 / 256, 6, "8-bit");
  }

  @Test
  void falsePositiveRate16() {
    BinaryFuseFilter f = BinaryFuse16.build(randomKeys(1_000_000, 43));
    int queries = 20_000_000;
    long fp = countPositives(f, queries, 4343);
    assertBinomial(fp, queries, 1.0 / 65536, 6, "16-bit");
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void falsePositiveRateSmallFilters(int bits) {
    // Many small filters: the aggregate FPR must still be about 2^-bits.
    long fp = 0;
    long trials = 0;
    for (int n = 2; n < 2000; n += 7) {
      BinaryFuseFilter f = build(bits, randomKeys(n, n));
      int q = bits == 8 ? 2000 : 40_000;
      fp += countPositives(f, q, ~n);
      trials += q;
    }
    assertBinomial(fp, trials, 1.0 / (1 << bits), 6, bits + "-bit small filters");
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void duplicateKeys(int bits) {
    long[] distinct = randomKeys(50_000, 7);
    // Every key twice, adjacent and interleaved, plus a few keys many times.
    long[] keys = new long[distinct.length * 2 + 1000];
    for (int i = 0; i < distinct.length; i++) {
      keys[2 * i] = distinct[i];
      keys[2 * i + 1] = distinct[(i + 17) % distinct.length];
    }
    for (int i = 0; i < 1000; i++) {
      keys[2 * distinct.length + i] = distinct[i % 3];
    }
    long[] copy = keys.clone();
    BinaryFuseFilter f = build(bits, keys);
    assertArrayEquals(copy, keys, "input must not be modified");
    assertEquals(distinct.length, f.keyCount());
    assertAllPresent(f, distinct);

    // Small sets with heavy duplication.
    for (int n = 1; n < 300; n++) {
      long[] few = randomKeys(1 + n % 5, n);
      long[] many = new long[n];
      for (int i = 0; i < n; i++) {
        many[i] = few[i % few.length];
      }
      BinaryFuseFilter g = build(bits, many);
      assertAllPresent(g, many);
      assertEquals(Math.min(n, few.length), g.keyCount());
    }
    // All keys equal.
    long[] same = new long[10_000];
    Arrays.fill(same, 99);
    BinaryFuseFilter h = build(bits, same);
    assertTrue(h.contains(99));
    assertEquals(1, h.keyCount());
  }

  @Test
  void constructionIsDeterministic() {
    long[] keys = randomKeys(100_000, 11);
    assertArrayEquals(BinaryFuse8.build(keys).toByteArray(), BinaryFuse8.build(keys).toByteArray());
    assertArrayEquals(BinaryFuse16.build(keys).toByteArray(),
        BinaryFuse16.build(keys).toByteArray());
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void serializationRoundTrip(int bits) {
    for (int n : new int[] {0, 1, 2, 3, 100, 12_345, 200_000}) {
      long[] keys = randomKeys(n, n);
      BinaryFuseFilter f = build(bits, keys);
      byte[] bytes = f.toByteArray();
      assertEquals(f.serializedSize(), bytes.length);

      BinaryFuseFilter loaded = BinaryFuseFilter.load(bytes);
      assertEquals(bits == 8 ? BinaryFuse8.class : BinaryFuse16.class, loaded.getClass());
      assertArrayEquals(bytes, loaded.toByteArray());
      assertEquals(f.keyCount(), loaded.keyCount());

      BinaryFuseFilter view = BinaryFuseFilter.wrap(ByteBuffer.wrap(bytes));
      assertArrayEquals(bytes, view.toByteArray());
      assertEquals(f.keyCount(), view.keyCount());
      assertEquals(bits, view.fingerprintBits());
      assertEquals(bytes.length, view.serializedSize());
      assertAllPresent(loaded, keys);
      assertAllPresent(view, keys);
      assertSameAnswers(f, loaded, 20_000, n);
      assertSameAnswers(f, view, 20_000, n);

      // Serialize at an offset into a larger direct buffer with the "wrong" byte order.
      ByteBuffer out = ByteBuffer.allocateDirect(bytes.length + 13).order(ByteOrder.BIG_ENDIAN);
      out.position(5);
      f.serialize(out);
      assertEquals(5 + bytes.length, out.position());
      assertEquals(ByteOrder.BIG_ENDIAN, out.order());
      out.position(5);
      BinaryFuseFilter offsetView = BinaryFuseFilter.wrap(out);
      assertEquals(5, out.position());
      assertSameAnswers(f, offsetView, 20_000, n + 1);
      assertSameAnswers(f, BinaryFuseFilter.load(out), 20_000, n + 1);
      // A view re-serializes to the identical bytes.
      ByteBuffer again = ByteBuffer.allocate(bytes.length);
      offsetView.serialize(again);
      assertArrayEquals(bytes, again.array());
    }
  }

  static void assertSameAnswers(BinaryFuseFilter a, BinaryFuseFilter b, int queries, long seed) {
    SplittableRandom r = new SplittableRandom(seed);
    for (int i = 0; i < queries; i++) {
      long k = r.nextLong();
      assertEquals(a.contains(k), b.contains(k));
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void offHeapMemoryMappedFile(int bits, @TempDir Path dir) throws IOException {
    long[] keys = randomKeys(500_000, 5);
    BinaryFuseFilter f = build(bits, keys);
    Path file = dir.resolve("filter.bin");
    Files.write(file, f.toByteArray());
    try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
      MappedByteBuffer mapped = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size());
      BinaryFuseFilter view = BinaryFuseFilter.wrap(mapped);
      assertAllPresent(view, keys);
      assertSameAnswers(f, view, 1_000_000, 55);
      assertEquals(f.keyCount(), view.keyCount());
      assertSameAnswers(f, BinaryFuseFilter.load(mapped), 100_000, 56);
    }
    // Serialize straight into a writable mapping.
    Path file2 = dir.resolve("filter2.bin");
    try (FileChannel ch = FileChannel.open(file2, StandardOpenOption.CREATE_NEW,
        StandardOpenOption.READ, StandardOpenOption.WRITE)) {
      MappedByteBuffer mapped = ch.map(FileChannel.MapMode.READ_WRITE, 0, f.serializedSize());
      f.serialize(mapped);
      mapped.force();
    }
    assertArrayEquals(f.toByteArray(), Files.readAllBytes(file2));
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void byteArrayKeys(int bits) {
    List<byte[]> keys = new ArrayList<>();
    for (int i = 0; i < 20_000; i++) {
      keys.add(("key-" + i).getBytes(StandardCharsets.UTF_8));
    }
    BinaryFuseFilter f = buildFromBytes(bits, keys);
    BinaryFuseFilter view = BinaryFuseFilter.wrap(ByteBuffer.wrap(f.toByteArray()));
    for (byte[] k : keys) {
      assertTrue(f.contains(k));
      assertTrue(view.contains(k));
      assertTrue(f.contains(WyHash.hash(k)));
      byte[] padded = new byte[k.length + 4];
      System.arraycopy(k, 0, padded, 2, k.length);
      assertTrue(f.contains(padded, 2, k.length));
      ByteBuffer direct = ByteBuffer.allocateDirect(padded.length);
      direct.put(padded).position(2).limit(2 + k.length);
      assertTrue(view.contains(direct));
      assertEquals(2, direct.position());
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void structuredKeys(int bits) {
    // Sequential zero-padded decimal strings: highly structured input.
    int n = 1_000_000;
    List<byte[]> keys = new ArrayList<>(n);
    Set<Long> hashes = new HashSet<>(2 * n);
    for (int i = 0; i < n; i++) {
      byte[] k = String.format("%016d", i).getBytes(StandardCharsets.US_ASCII);
      keys.add(k);
      assertTrue(hashes.add(WyHash.hash(k)), "64-bit wyhash collision");
    }
    BinaryFuseFilter f = buildFromBytes(bits, keys);
    assertEquals(n, f.keyCount());
    for (byte[] k : keys) {
      assertTrue(f.contains(k));
    }
    // Queries: the next structured strings, which are not in the set.
    int queries = bits == 8 ? 1_000_000 : 10_000_000;
    long fp = 0;
    byte[] q = new byte[16];
    for (int i = n; i < n + queries; i++) {
      long v = i;
      for (int j = 15; j >= 0; j--) {
        q[j] = (byte) ('0' + v % 10);
        v /= 10;
      }
      if (f.contains(q)) {
        fp++;
      }
    }
    assertBinomial(fp, queries, 1.0 / (1 << bits), 6, bits + "-bit structured");
  }

  @Test
  void viewsAndHeapFiltersAgreeOnByteKeys() {
    long[] keys = randomKeys(30_000, 77);
    for (int bits : new int[] {8, 16}) {
      BinaryFuseFilter f = build(bits, keys);
      ByteBuffer direct = ByteBuffer.allocateDirect(f.serializedSize());
      f.serialize(direct);
      direct.flip();
      BinaryFuseFilter view = BinaryFuseFilter.wrap(direct.asReadOnlyBuffer());
      SplittableRandom r = new SplittableRandom(1);
      byte[] k = new byte[24];
      for (int i = 0; i < 100_000; i++) {
        r.nextBytes(k);
        assertEquals(f.contains(k), view.contains(k));
      }
    }
  }

  // ------------------------------------------------------------ corruption

  static byte[] sample(int bits) {
    return build(bits, randomKeys(1000, 3)).toByteArray();
  }

  static void assertRejected(byte[] bytes, String messagePart) {
    InvalidFilterException e1 = assertThrows(InvalidFilterException.class,
        () -> BinaryFuseFilter.load(bytes));
    assertTrue(e1.getMessage().contains(messagePart), e1.getMessage());
    InvalidFilterException e2 = assertThrows(InvalidFilterException.class,
        () -> BinaryFuseFilter.wrap(ByteBuffer.wrap(bytes)));
    assertTrue(e2.getMessage().contains(messagePart), e2.getMessage());
  }

  /** Sets a header field and recomputes the header checksum, to test semantic checks. */
  static byte[] withField(byte[] bytes, int offset, int size, long value) {
    byte[] b = bytes.clone();
    ByteBuffer bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
    switch (size) {
      case 1 -> bb.put(offset, (byte) value);
      case 4 -> bb.putInt(offset, (int) value);
      default -> bb.putLong(offset, value);
    }
    bb.putInt(Fuse.OFF_HEADER_CRC, Fuse.crc32c(bb, 0, Fuse.OFF_HEADER_CRC));
    return b;
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 16})
  void rejectsCorruptInput(int bits) {
    byte[] good = sample(bits);
    assertRejected(new byte[0], "too short");
    assertRejected(Arrays.copyOf(good, Fuse.HEADER_SIZE - 1), "too short");
    assertRejected(Arrays.copyOf(good, good.length - 1), "truncated");

    byte[] badMagic = good.clone();
    badMagic[0] ^= 1;
    assertRejected(badMagic, "magic");

    assertRejected(withField(good, Fuse.OFF_VERSION, 1, 2), "version");
    assertRejected(withField(good, Fuse.OFF_BITS, 1, 32), "fingerprint size");
    assertRejected(withField(good, Fuse.OFF_ARITY, 1, 4), "arity");
    assertRejected(withField(good, Fuse.OFF_FLAGS, 1, 1), "flags");
    assertRejected(withField(good, Fuse.OFF_SEGMENT_LENGTH, 4, 3), "segment length");
    assertRejected(withField(good, Fuse.OFF_SEGMENT_LENGTH, 4, 1 << 19), "segment length");
    assertRejected(withField(good, Fuse.OFF_SEGMENT_COUNT, 4, 0), "segment count");
    assertRejected(withField(good, Fuse.OFF_SEGMENT_COUNT, 4, 1L << 31), "array length");
    assertRejected(withField(good, Fuse.OFF_ARRAY_LENGTH, 4, 0xFFFFFFFFL), "array length");
    assertRejected(withField(good, Fuse.OFF_KEYS, 4, 0), "array length");
    assertRejected(withField(good, Fuse.OFF_KEYS, 4, 0xFFFFFFFFL), "key count");
    // Claiming 16-bit fingerprints for an 8-bit payload makes it too short, and vice versa
    // the declared variant must match the bytes.
    if (bits == 8) {
      assertRejected(withField(good, Fuse.OFF_BITS, 1, 16), "truncated");
    }

    // Header bit flips are caught by the header checksum.
    for (int i = 4; i < Fuse.HEADER_SIZE; i++) {
      byte[] b = good.clone();
      b[i] ^= 0x10;
      assertThrows(InvalidFilterException.class, () -> BinaryFuseFilter.load(b), "byte " + i);
      assertThrows(InvalidFilterException.class,
          () -> BinaryFuseFilter.wrap(ByteBuffer.wrap(b)), "byte " + i);
    }
    // Fingerprint corruption is caught by load (wrap does not checksum the payload).
    byte[] badPayload = good.clone();
    badPayload[Fuse.HEADER_SIZE + 17] ^= 1;
    InvalidFilterException e = assertThrows(InvalidFilterException.class,
        () -> BinaryFuseFilter.load(badPayload));
    assertTrue(e.getMessage().contains("fingerprint checksum"), e.getMessage());
    BinaryFuseFilter.wrap(ByteBuffer.wrap(badPayload));

    // Trailing bytes are allowed.
    byte[] longer = Arrays.copyOf(good, good.length + 100);
    assertEquals(good.length, BinaryFuseFilter.load(longer).serializedSize());
  }

  @Test
  void serializeRejectsSmallOrReadOnlyBuffers() {
    BinaryFuseFilter f = BinaryFuse8.build(randomKeys(100, 1));
    assertThrows(java.nio.BufferOverflowException.class,
        () -> f.serialize(ByteBuffer.allocate(f.serializedSize() - 1)));
    assertThrows(java.nio.ReadOnlyBufferException.class,
        () -> f.serialize(ByteBuffer.allocate(f.serializedSize()).asReadOnlyBuffer()));
  }

  @Test
  void fewConstructionAttempts() {
    int worst = 0;
    for (int n = 1; n <= 3000; n++) {
      worst = Math.max(worst, Fuse.peel(randomKeys(n, ~n), Fuse.Layout.forSize(n, 8)).attempts());
    }
    for (int n : new int[] {10_000, 100_000, 1_000_000}) {
      for (int s = 0; s < 3; s++) {
        worst = Math.max(worst,
            Fuse.peel(randomKeys(n, n + s), Fuse.Layout.forSize(n, 8)).attempts());
      }
    }
    assertTrue(worst <= 4, "needed " + worst + " attempts");
  }

  @Test
  void layoutMatchesReference() {
    // Spot checks of the C/Go parameter formulas.
    Fuse.Layout l = Fuse.Layout.forSize(1_000_000, 8);
    assertEquals(1 << 13, l.segmentLength());
    assertEquals(1_130_496, l.arrayLength());
    assertEquals(1 << 17, Fuse.Layout.forSize(100_000_000, 8).segmentLength());
    assertEquals(1 << 18, Fuse.Layout.forSize(500_000_000, 8).segmentLength());
    assertThrows(IllegalArgumentException.class, () -> Fuse.Layout.forSize(1_500_000_000, 16));
    assertThrows(IllegalArgumentException.class,
        () -> Fuse.Layout.forSize(Integer.MAX_VALUE, 8));
    for (int n = 2; n < 100_000; n = n * 3 / 2 + 1) {
      Fuse.Layout x = Fuse.Layout.forSize(n, 8);
      assertEquals((x.segmentCount() + 2L) * x.segmentLength(), x.arrayLength());
      assertTrue(x.arrayLength() >= n);
    }
  }

  @Test
  void viewDoesNotDependOnBufferState() {
    BinaryFuseFilter f = BinaryFuse16.build(randomKeys(5000, 9));
    ByteBuffer buf = ByteBuffer.wrap(f.toByteArray());
    BinaryFuseFilter view = BinaryFuseFilter.wrap(buf);
    buf.position(100).limit(200).order(ByteOrder.LITTLE_ENDIAN);
    assertSameAnswers(f, view, 50_000, 3);
  }
}
