package io.github.fastfilter.jbinfuse;

import static io.github.fastfilter.jbinfuse.ConstMapTest.NOT_FOUND;
import static io.github.fastfilter.jbinfuse.ConstMapTest.checkInterop;
import static io.github.fastfilter.jbinfuse.ConstMapTest.keys;
import static io.github.fastfilter.jbinfuse.ConstMapTest.resource;
import static io.github.fastfilter.jbinfuse.ConstMapTest.values;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Zero-copy views: {@code wrap(ByteBuffer)} on the three kinds of constant map. */
class ConstMapViewTest {

  /** The bytes at {@code offset} in a buffer of the given kind, with garbage around them. */
  static ByteBuffer place(byte[] bytes, int offset, boolean direct, ByteOrder order) {
    ByteBuffer b = direct ? ByteBuffer.allocateDirect(offset + bytes.length + 11)
        : ByteBuffer.allocate(offset + bytes.length + 11);
    for (int i = 0; i < b.capacity(); i++) {
      b.put(i, (byte) (0xA5 ^ i));
    }
    b.put(offset, bytes);
    b.position(offset);
    b.order(order);
    return b;
  }

  static Object wrap(String ext, ByteBuffer b) {
    return switch (ext) {
      case "cmap" -> ConstMap.wrap(b);
      case "vmap" -> VerifiedConstMap.wrap(b);
      default -> PairedVerifiedConstMap.wrap(b);
    };
  }

  static ConstMapTest.Lookup lookup(Object view) {
    if (view instanceof ConstMap c) {
      return c::get;
    } else if (view instanceof VerifiedConstMap v) {
      return v::get;
    }
    return ((PairedVerifiedConstMap) view)::get;
  }

  static byte[] bytes(Object view) {
    if (view instanceof ConstMap c) {
      return c.toByteArray();
    } else if (view instanceof VerifiedConstMap v) {
      return v.toByteArray();
    }
    return ((PairedVerifiedConstMap) view).toByteArray();
  }

  /**
   * Files written by rsconstmap (Rust) and fastconstmap (C/Python), which include Go's
   * 28-byte CMAP0001 header, fastconstmap's CMAP0003 and its key count in the pad word of
   * VMAP0001 and PMAP0001, wrapped at every alignment, from heap and direct buffers in either
   * byte order: the answers are those of the original maps, the buffer is untouched, and the
   * view serializes to the very bytes it wraps.
   */
  @ParameterizedTest
  @ValueSource(strings = {"rust.cmap", "rust.vmap", "rust.pmap", "fastconstmap.cmap",
      "fastconstmap.vmap", "fastconstmap.pmap"})
  void wrapsFilesOfTheOtherImplementations(String name) throws IOException {
    byte[] file = resource(name);
    String ext = name.substring(name.length() - 4);
    boolean verified = !ext.equals("cmap");
    for (int offset = 0; offset < 16; offset++) {
      for (boolean direct : new boolean[] {false, true}) {
        for (ByteOrder order : new ByteOrder[] {ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN}) {
          ByteBuffer b = place(file, offset, direct, order);
          int limit = b.limit();
          Object view = wrap(ext, b);
          String id = name + " offset " + offset + (direct ? " direct " : " heap ") + order;
          checkInterop(id, lookup(view), verified);
          assertEquals(offset, b.position(), id);
          assertEquals(limit, b.limit(), id);
          assertEquals(order, b.order(), id);
          assertArrayEquals(file, bytes(view), id);
        }
      }
    }
  }

  /** The bytes a view writes are a valid file for the on-heap loaders, and the same map. */
  @Test
  void viewBytesLoadAndViewsAgreeWithLoadedMaps() throws IOException {
    for (String src : new String[] {"rust", "fastconstmap"}) {
      byte[] c = resource(src + ".cmap");
      byte[] v = resource(src + ".vmap");
      byte[] p = resource(src + ".pmap");
      ConstMap cv = ConstMap.wrap(ByteBuffer.wrap(c));
      VerifiedConstMap vv = VerifiedConstMap.wrap(ByteBuffer.wrap(v));
      PairedVerifiedConstMap pv = PairedVerifiedConstMap.wrap(ByteBuffer.wrap(p));
      checkInterop(src, ConstMap.load(cv.toByteArray())::get, false);
      checkInterop(src, VerifiedConstMap.load(vv.toByteArray())::get, true);
      checkInterop(src, PairedVerifiedConstMap.load(pv.toByteArray())::get, true);
      assertEquals(ConstMap.load(c).arrayLength(), cv.arrayLength());
      assertEquals(VerifiedConstMap.load(v).arrayLength(), vv.arrayLength());
      assertEquals(PairedVerifiedConstMap.load(p).arrayLength(), pv.arrayLength());
      // Converting a view of a VMAP to the paired layout gives the PMAP the others wrote,
      // apart from the pad word that fastconstmap fills with its key count.
      byte[] paired = vv.paired().toByteArray();
      byte[] expected = resource("rust.pmap");
      assertArrayEquals(expected, paired, src);
    }
  }

  @Test
  void wrapsMemoryMappedFiles(@TempDir Path dir) throws IOException {
    for (String name : new String[] {"rust.cmap", "fastconstmap.cmap", "rust.vmap",
        "fastconstmap.vmap", "rust.pmap", "fastconstmap.pmap"}) {
      // At an odd offset inside a larger file, as when maps are embedded in a container.
      byte[] file = resource(name);
      byte[] container = new byte[file.length + 100];
      System.arraycopy(file, 0, container, 37, file.length);
      Path path = dir.resolve(name);
      Files.write(path, container);
      try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
        MappedByteBuffer mapped = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size());
        mapped.position(37);
        String ext = name.substring(name.length() - 4);
        Object view = wrap(ext, mapped);
        checkInterop(name, lookup(view), !ext.equals("cmap"));
        assertArrayEquals(file, bytes(view), name);
      }
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 5, 100, 1001, 30000})
  void viewsAnswerLikeOnHeapMaps(int n) {
    List<String> k = keys("v-", n);
    long[] v = values(n);
    ConstMap cm = ConstMap.build(k, v);
    VerifiedConstMap vm = VerifiedConstMap.build(k, v);
    PairedVerifiedConstMap pm = vm.paired();
    ConstMap cv = ConstMap.wrap(place(cm.toByteArray(), 3, true, ByteOrder.BIG_ENDIAN));
    VerifiedConstMap vv = VerifiedConstMap.wrap(place(vm.toByteArray(), 5, true,
        ByteOrder.BIG_ENDIAN));
    PairedVerifiedConstMap pv = PairedVerifiedConstMap.wrap(place(pm.toByteArray(), 7, false,
        ByteOrder.LITTLE_ENDIAN));
    List<String> queries = new ArrayList<>(k);
    SplittableRandom r = new SplittableRandom(n);
    for (int i = 0; i < 2000; i++) {
      queries.add("absent-" + r.nextLong());
    }
    for (String q : queries) {
      assertEquals(cm.get(q), cv.get(q));
      assertEquals(vm.get(q), vv.get(q));
      assertEquals(pm.get(q), pv.get(q));
      byte[] qb = q.getBytes(java.nio.charset.StandardCharsets.UTF_8);
      assertEquals(vm.get(qb), vv.get(ByteBuffer.wrap(qb)));
    }
    assertArrayEquals(cm.getMany(queries), cv.getMany(queries));
    assertArrayEquals(vm.getMany(queries), vv.getMany(queries));
    assertArrayEquals(pm.getMany(queries), pv.getMany(queries));
    assertArrayEquals(cm.toByteArray(), cv.toByteArray());
    assertArrayEquals(vm.toByteArray(), vv.toByteArray());
    assertArrayEquals(pm.toByteArray(), pv.toByteArray());
    assertArrayEquals(pm.toByteArray(), vv.paired().toByteArray());
    assertEquals(cm.serializedSize(), cv.serializedSize());
    assertEquals(vm.arrayLength(), vv.arrayLength());
    assertEquals(pm.arrayLength(), pv.arrayLength());
    if (n == 0) {
      assertEquals(NOT_FOUND, vv.get("x"));
      assertEquals(NOT_FOUND, pv.get("x"));
    }
  }

  @Test
  void viewSerializesAtThePositionAndAdvancesIt() {
    VerifiedConstMap vm = VerifiedConstMap.build(keys("s", 50), values(50));
    VerifiedConstMap view = VerifiedConstMap.wrap(ByteBuffer.wrap(vm.toByteArray()));
    ByteBuffer out = ByteBuffer.allocate(view.serializedSize() + 9);
    out.position(9);
    view.serialize(out);
    assertEquals(out.capacity(), out.position());
    out.position(9);
    assertArrayEquals(vm.toByteArray(), VerifiedConstMap.load(out).toByteArray());
    assertThrows(java.nio.BufferOverflowException.class,
        () -> view.serialize(ByteBuffer.allocate(view.serializedSize() - 1)));
    assertThrows(java.nio.ReadOnlyBufferException.class,
        () -> view.serialize(ByteBuffer.allocate(view.serializedSize()).asReadOnlyBuffer()));
  }

  @Test
  void wrapRefusesWhatLoadRefuses() throws IOException {
    for (String name : new String[] {"fastconstmap-0.9.cmap", "fastconstmap-0.9.vmap"}) {
      ByteBuffer b = ByteBuffer.wrap(resource(name));
      for (String ext : new String[] {"cmap", "vmap", "pmap"}) {
        InvalidFilterException e = assertThrows(InvalidFilterException.class,
            () -> wrap(ext, b));
        assertTrue(e.getMessage().contains("fastconstmap 0.9"), e.getMessage());
      }
    }
    assertThrows(InvalidFilterException.class,
        () -> ConstMap.wrap(ByteBuffer.wrap(resource("rust.vmap"))));
    assertThrows(InvalidFilterException.class,
        () -> VerifiedConstMap.wrap(ByteBuffer.wrap(resource("rust.pmap"))));
    assertThrows(InvalidFilterException.class,
        () -> PairedVerifiedConstMap.wrap(ByteBuffer.wrap(resource("rust.cmap"))));
    for (String name : new String[] {"rust.cmap", "fastconstmap.cmap", "rust.vmap",
        "rust.pmap"}) {
      byte[] good = resource(name);
      String ext = name.substring(name.length() - 4);
      for (int len = 0; len < good.length; len += 7) {
        ByteBuffer cut = ByteBuffer.wrap(good, 0, len);
        assertThrows(InvalidFilterException.class, () -> wrap(ext, cut), name + " " + len);
      }
      // Header fields that do not describe the array, under a valid checksum.
      for (int[] e : new int[][] {{16, 3}, {16, 0}, {20, 0}, {20, -1}, {24, 1}}) {
        byte[] bad = good.clone();
        ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putInt(e[0], e[1]);
        assertThrows(InvalidFilterException.class, () -> wrap(ext, ByteBuffer.wrap(bad)),
            name + " offset " + e[0]);
      }
    }
  }

  /**
   * wrap runs in constant time and so does not verify the checksum; load does. On corrupt
   * array bytes a view gives wrong answers but never reads outside the map.
   */
  @Test
  void corruptArraysAreCaughtByLoadButNeverReadOutOfBoundsByViews() throws IOException {
    byte[] bad = resource("rust.pmap");
    for (int i = 40; i < bad.length - 8; i += 3) {
      bad[i] ^= (byte) (i * 31);
    }
    assertThrows(InvalidFilterException.class, () -> PairedVerifiedConstMap.load(bad));
    PairedVerifiedConstMap view = PairedVerifiedConstMap.wrap(ByteBuffer.wrap(bad));
    SplittableRandom r = new SplittableRandom(1);
    for (int i = 0; i < 100000; i++) {
      view.getByHash(r.nextLong());
    }
  }
}
