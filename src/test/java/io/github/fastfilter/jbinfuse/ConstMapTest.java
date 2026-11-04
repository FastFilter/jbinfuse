package io.github.fastfilter.jbinfuse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ConstMapTest {

  static final long NOT_FOUND = VerifiedConstMap.NOT_FOUND;

  static byte[] resource(String name) throws IOException {
    try (InputStream in = ConstMapTest.class.getResourceAsStream("/constmap/" + name)) {
      if (in == null) {
        throw new IOException("missing resource " + name);
      }
      return in.readAllBytes();
    }
  }

  static List<String> keys(String prefix, int n) {
    List<String> keys = new ArrayList<>(n);
    for (int i = 0; i < n; i++) {
      keys.add(prefix + i);
    }
    return keys;
  }

  static long[] values(int n) {
    long[] v = new long[n];
    for (int i = 0; i < n; i++) {
      v[i] = i * 0x9E3779B97F4A7C15L;
    }
    return v;
  }

  // ---------------------------------------------------------------------------------------
  // Interoperability with the Go, Rust and C implementations.
  //
  // src/test/resources/constmap/ holds the interop files of github.com/lemire/constmap
  // (testdata/interop at commit 6f9f4a9): rust.* from rsconstmap, fastconstmap.* from
  // fastconstmap 0.10+, and fastconstmap-0.9.* from the legacy XXH3 format. All were built
  // from keys "key-i" mapped to 7 * i, for i in [0, 200).

  static final List<String> INTEROP_KEYS = keys("key-", 200);

  static long[] interopValues() {
    long[] v = new long[200];
    for (int i = 0; i < 200; i++) {
      v[i] = 7L * i;
    }
    return v;
  }

  interface Lookup {
    long get(String key);
  }

  static void checkInterop(String name, Lookup map, boolean verified) {
    long[] v = interopValues();
    for (int i = 0; i < 200; i++) {
      assertEquals(v[i], map.get(INTEROP_KEYS.get(i)), name + " key-" + i);
    }
    if (verified) {
      for (int i = 0; i < 1000; i++) {
        assertEquals(NOT_FOUND, map.get("absent-" + i), name + " absent-" + i);
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"rust", "fastconstmap"})
  void readsOtherImplementations(String src) throws IOException {
    checkInterop(src + ".cmap", ConstMap.load(resource(src + ".cmap"))::get, false);
    checkInterop(src + ".vmap", VerifiedConstMap.load(resource(src + ".vmap"))::get, true);
    checkInterop(src + ".pmap", PairedVerifiedConstMap.load(resource(src + ".pmap"))::get,
        true);
  }

  @Test
  void writesTheSameBytesAsGoAndRust() throws IOException {
    long[] v = interopValues();
    VerifiedConstMap vm = VerifiedConstMap.build(INTEROP_KEYS, v);
    assertArrayEquals(resource("rust.cmap"), ConstMap.build(INTEROP_KEYS, v).toByteArray());
    assertArrayEquals(resource("rust.vmap"), vm.toByteArray());
    assertArrayEquals(resource("rust.pmap"), vm.paired().toByteArray());
    assertArrayEquals(resource("rust.pmap"),
        PairedVerifiedConstMap.build(INTEROP_KEYS, v).toByteArray());
  }

  @Test
  void writesWhatFastconstmapWritesApartFromTheKeyCount() throws IOException {
    long[] v = interopValues();
    byte[] ours = ConstMap.build(INTEROP_KEYS, v).toByteArray();
    byte[] theirs = resource("fastconstmap.cmap");
    assertEquals("CMAP0003", new String(theirs, 0, 8, StandardCharsets.US_ASCII));
    assertArrayEquals(Arrays.copyOfRange(ours, 8, 28), Arrays.copyOfRange(theirs, 8, 28));
    assertEquals(200, ByteBuffer.wrap(theirs).order(ByteOrder.LITTLE_ENDIAN).getInt(28));
    assertArrayEquals(Arrays.copyOfRange(ours, 28, ours.length - 8),
        Arrays.copyOfRange(theirs, 32, theirs.length - 8));
    VerifiedConstMap vm = VerifiedConstMap.build(INTEROP_KEYS, v);
    for (String ext : new String[] {"vmap", "pmap"}) {
      byte[] mine = ext.equals("vmap") ? vm.toByteArray() : vm.paired().toByteArray();
      byte[] c = resource("fastconstmap." + ext);
      assertArrayEquals(Arrays.copyOfRange(mine, 0, 28), Arrays.copyOfRange(c, 0, 28), ext);
      assertArrayEquals(Arrays.copyOfRange(mine, 32, mine.length - 8),
          Arrays.copyOfRange(c, 32, c.length - 8), ext);
    }
  }

  @Test
  void legacyFastconstmapFilesAreNamed() throws IOException {
    for (String name : new String[] {"fastconstmap-0.9.cmap", "fastconstmap-0.9.vmap"}) {
      byte[] b = resource(name);
      for (Runnable load : List.<Runnable>of(() -> ConstMap.load(b),
          () -> VerifiedConstMap.load(b), () -> PairedVerifiedConstMap.load(b))) {
        InvalidFilterException e = assertThrows(InvalidFilterException.class, load::run);
        assertTrue(e.getMessage().contains("fastconstmap 0.9"), e.getMessage());
      }
    }
  }

  @Test
  void wrongKindIsNamed() throws IOException {
    InvalidFilterException e = assertThrows(InvalidFilterException.class,
        () -> ConstMap.load(resource("rust.vmap")));
    assertTrue(e.getMessage().contains("VerifiedConstMap"), e.getMessage());
    e = assertThrows(InvalidFilterException.class,
        () -> VerifiedConstMap.load(resource("rust.pmap")));
    assertTrue(e.getMessage().contains("PairedVerifiedConstMap"), e.getMessage());
    e = assertThrows(InvalidFilterException.class,
        () -> PairedVerifiedConstMap.load(resource("rust.cmap")));
    assertTrue(e.getMessage().contains("is a ConstMap"), e.getMessage());
  }

  /**
   * Checks the bytes written for many sizes and two key sets (one non-ASCII) against
   * github.com/lemire/constmap itself (tools/constmap_vectors): same size and same trailing
   * FNV-1a checksum, which covers every other byte. This exercises the small-size
   * parameters, the retries with halved and doubled segments below a million keys, and the
   * path without them above.
   */
  @Test
  void matchesGoReferenceForManySizes() throws IOException {
    int checked = 0;
    try (BufferedReader r = new BufferedReader(new InputStreamReader(
        ConstMapTest.class.getResourceAsStream("/constmap_vectors.txt"),
        StandardCharsets.UTF_8))) {
      String last = null;
      ConstMap cm = null;
      VerifiedConstMap vm = null;
      for (String line; (line = r.readLine()) != null; ) {
        String[] f = line.split(" ");
        String prefix = f[1];
        int n = Integer.parseInt(f[2]);
        String id = prefix + n;
        if (!id.equals(last)) {
          List<String> k = keys(prefix, n);
          long[] v = values(n);
          cm = ConstMap.build(k, v);
          vm = VerifiedConstMap.build(k, v);
          last = id;
          if (n <= 100000) {
            for (int i = 0; i < n; i++) {
              assertEquals(v[i], cm.get(k.get(i)));
              assertEquals(v[i], vm.get(k.get(i)));
            }
          }
        }
        byte[] bytes = switch (f[0]) {
          case "C" -> cm.toByteArray();
          case "V" -> vm.toByteArray();
          default -> vm.paired().toByteArray();
        };
        assertEquals(Integer.parseInt(f[3]), bytes.length, line);
        long sum = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            .getLong(bytes.length - 8);
        assertEquals(Long.parseUnsignedLong(f[4], 16), sum, line);
        checked++;
      }
    }
    assertTrue(checked > 150);
  }

  // ---------------------------------------------------------------------------------------
  // Behavior.

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3, 5, 17, 1000, 50000})
  void allKindsAgree(int n) {
    List<String> k = keys("k", n);
    long[] v = values(n);
    ConstMap cm = ConstMap.build(k, v);
    VerifiedConstMap vm = VerifiedConstMap.build(k, v);
    PairedVerifiedConstMap pm = PairedVerifiedConstMap.build(k, v);
    for (int i = 0; i < n; i++) {
      String key = k.get(i);
      byte[] b = key.getBytes(StandardCharsets.UTF_8);
      assertEquals(v[i], cm.get(key));
      assertEquals(v[i], cm.get(b));
      assertEquals(v[i], vm.get(key));
      assertEquals(v[i], vm.get(ByteBuffer.wrap(b)));
      assertEquals(v[i], pm.get(key));
      assertEquals(v[i], pm.getByHash(XxHash64.hash(b)));
      assertTrue(vm.containsKey(key));
      assertTrue(pm.containsKey(key));
    }
    SplittableRandom rnd = new SplittableRandom(n);
    for (int i = 0; i < 10000; i++) {
      String absent = "absent-" + rnd.nextLong();
      assertEquals(NOT_FOUND, vm.get(absent));
      assertEquals(NOT_FOUND, pm.get(absent));
      assertFalse(vm.containsKey(absent));
    }
    assertEquals(vm.arrayLength(), cm.arrayLength());
    assertEquals(vm.arrayLength(), pm.arrayLength());
    assertEquals(vm.serializedSize(), pm.serializedSize());
  }

  @Test
  void byteKeysMatchStringKeys() {
    List<String> k = keys("é-", 300);
    List<byte[]> b = new ArrayList<>();
    for (String s : k) {
      b.add(s.getBytes(StandardCharsets.UTF_8));
    }
    long[] v = values(300);
    assertArrayEquals(ConstMap.build(k, v).toByteArray(),
        ConstMap.buildFromBytes(b, v).toByteArray());
    assertArrayEquals(VerifiedConstMap.build(k, v).toByteArray(),
        VerifiedConstMap.buildFromBytes(b, v).toByteArray());
    assertArrayEquals(PairedVerifiedConstMap.build(k, v).toByteArray(),
        PairedVerifiedConstMap.buildFromBytes(b, v).toByteArray());
    ConstMap cm = ConstMap.buildFromBytes(b, v);
    byte[] padded = new byte[64];
    byte[] key = b.get(42);
    System.arraycopy(key, 0, padded, 9, key.length);
    assertEquals(v[42], cm.get(padded, 9, key.length));
    ByteBuffer direct = ByteBuffer.allocateDirect(64);
    direct.position(3);
    direct.put(key);
    direct.flip().position(3);
    assertEquals(v[42], cm.get(direct));
    assertEquals(3, direct.position());
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 7, 8, 9, 100, 1001})
  void getManyMatchesGet(int n) {
    List<String> k = keys("m", n);
    long[] v = values(n);
    List<String> queries = new ArrayList<>(k);
    for (int i = 0; i < n / 2 + 3; i++) {
      queries.add("missing-" + i);
    }
    ConstMap cm = ConstMap.build(k, v);
    VerifiedConstMap vm = VerifiedConstMap.build(k, v);
    PairedVerifiedConstMap pm = vm.paired();
    long[] c = cm.getMany(queries);
    long[] w = vm.getMany(queries);
    long[] p = new long[queries.size() + 2];
    p[queries.size()] = 12345;
    pm.getMany(queries, p);
    for (int i = 0; i < queries.size(); i++) {
      String q = queries.get(i);
      assertEquals(cm.get(q), c[i]);
      assertEquals(vm.get(q), w[i]);
      assertEquals(pm.get(q), p[i]);
    }
    assertEquals(12345, p[queries.size()]);
    assertThrows(IndexOutOfBoundsException.class,
        () -> vm.getMany(queries, new long[queries.size() - 1]));
  }

  @Test
  void emptyMaps() {
    ConstMap cm = ConstMap.build(List.of(), new long[0]);
    VerifiedConstMap vm = VerifiedConstMap.build(List.of(), new long[0]);
    PairedVerifiedConstMap pm = vm.paired();
    assertEquals(NOT_FOUND, vm.get("x"));
    assertEquals(NOT_FOUND, pm.get("x"));
    cm.get("x"); // arbitrary value, but no exception
    assertEquals(0, ConstMap.load(cm.toByteArray()).arrayLength());
    assertEquals(NOT_FOUND, VerifiedConstMap.load(vm.toByteArray()).get("x"));
    assertEquals(NOT_FOUND, PairedVerifiedConstMap.load(pm.toByteArray()).get("x"));
  }

  @Test
  void roundTripsAtAnOffsetWithoutTouchingTheBuffer() {
    List<String> k = keys("r", 5000);
    long[] v = values(5000);
    VerifiedConstMap vm = VerifiedConstMap.build(k, v);
    ByteBuffer buf = ByteBuffer.allocateDirect(vm.serializedSize() + 20)
        .order(ByteOrder.BIG_ENDIAN);
    buf.position(13);
    vm.serialize(buf);
    assertEquals(13 + vm.serializedSize(), buf.position());
    assertEquals(ByteOrder.BIG_ENDIAN, buf.order());
    buf.position(13);
    VerifiedConstMap back = VerifiedConstMap.load(buf);
    assertEquals(13, buf.position());
    assertArrayEquals(vm.toByteArray(), back.toByteArray());
    for (int i = 0; i < 5000; i += 7) {
      assertEquals(v[i], back.get(k.get(i)));
    }

    ConstMap cm = ConstMap.build(k, v);
    assertArrayEquals(cm.toByteArray(), ConstMap.load(cm.toByteArray()).toByteArray());
    PairedVerifiedConstMap pm = vm.paired();
    assertArrayEquals(pm.toByteArray(),
        PairedVerifiedConstMap.load(pm.toByteArray()).toByteArray());

    assertThrows(java.nio.BufferOverflowException.class,
        () -> cm.serialize(ByteBuffer.allocate(cm.serializedSize() - 1)));
    assertThrows(java.nio.ReadOnlyBufferException.class,
        () -> cm.serialize(ByteBuffer.allocate(cm.serializedSize()).asReadOnlyBuffer()));
  }

  @Test
  void detectsCorruptionAndTruncation() throws IOException {
    for (String name : new String[] {"rust.cmap", "fastconstmap.cmap", "rust.vmap",
        "rust.pmap"}) {
      byte[] good = resource(name);
      for (int i = 0; i < good.length; i++) {
        byte[] bad = good.clone();
        bad[i] ^= 0x10;
        assertThrows(InvalidFilterException.class, () -> load(name, bad), name + " byte " + i);
      }
      for (int len = 0; len < good.length; len += 13) {
        byte[] cut = Arrays.copyOf(good, len);
        assertThrows(InvalidFilterException.class, () -> load(name, cut), name + " len " + len);
      }
    }
  }

  private static void load(String name, byte[] b) {
    if (name.endsWith("cmap")) {
      ConstMap.load(b);
    } else if (name.endsWith("vmap")) {
      VerifiedConstMap.load(b);
    } else {
      PairedVerifiedConstMap.load(b);
    }
  }

  /** Rewrites the FNV-1a checksum of a serialized map after editing it. */
  private static void reseal(byte[] b) {
    long h = ConstMaps.FNV_OFFSET;
    for (int i = 0; i < b.length - 8; i++) {
      h ^= b[i] & 0xFF;
      h *= ConstMaps.FNV_PRIME;
    }
    ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putLong(b.length - 8, h);
  }

  @Test
  void rejectsInconsistentParametersEvenWithAValidChecksum() throws IOException {
    byte[] good = resource("rust.vmap");
    ByteBuffer g = ByteBuffer.wrap(good).order(ByteOrder.LITTLE_ENDIAN);
    int segmentLength = g.getInt(16);
    int segmentCount = g.getInt(20);
    int[][] edits = {
        {16, segmentLength + 1},
        {16, 0},
        {16, segmentLength * 2},
        {20, 0},
        {20, segmentCount + 1},
        {20, -1},
    };
    for (int[] e : edits) {
      byte[] bad = good.clone();
      ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putInt(e[0], e[1]);
      reseal(bad);
      assertThrows(InvalidFilterException.class, () -> VerifiedConstMap.load(bad),
          "offset " + e[0] + " value " + e[1]);
    }
    // The pad word (fastconstmap's key count) is ignored.
    byte[] counted = good.clone();
    ByteBuffer.wrap(counted).order(ByteOrder.LITTLE_ENDIAN).putInt(28, 12345);
    reseal(counted);
    checkInterop("counted", VerifiedConstMap.load(counted)::get, true);
  }

  @Test
  void rejectsBadInput() {
    assertThrows(IllegalArgumentException.class,
        () -> ConstMap.build(List.of("a", "b"), new long[1]));
    assertThrows(IllegalArgumentException.class,
        () -> VerifiedConstMap.build(List.of("a", "b", "a"), new long[3]));
    assertThrows(IllegalArgumentException.class,
        () -> ConstMap.buildFromHashes(new long[] {5, 5}, new long[2]));
    List<String> many = keys("d", 1000);
    many.add("d500");
    assertThrows(IllegalArgumentException.class,
        () -> ConstMap.build(many, new long[many.size()]));
    assertThrows(InvalidFilterException.class, () -> ConstMap.load(new byte[40]));
  }

  @Test
  void valuesUseAll64Bits() {
    List<String> k = List.of("min", "max", "minus-one", "zero");
    long[] v = {Long.MIN_VALUE, Long.MAX_VALUE, -1L, 0};
    ConstMap cm = ConstMap.build(k, v);
    PairedVerifiedConstMap pm = PairedVerifiedConstMap.build(k, v);
    for (int i = 0; i < 4; i++) {
      assertEquals(v[i], cm.get(k.get(i)));
      assertEquals(v[i], pm.get(k.get(i)));
    }
    // A value equal to NOT_FOUND cannot be told from a missing key.
    assertFalse(pm.containsKey("minus-one"));
    assertNotEquals(NOT_FOUND, pm.get("zero"));
  }
}
