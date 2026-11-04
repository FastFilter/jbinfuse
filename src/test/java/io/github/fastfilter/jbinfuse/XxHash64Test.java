package io.github.fastfilter.jbinfuse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Checks XxHash64 against vectors produced by the reference C implementation
 * (tools/xxh64_vectors.c).
 */
class XxHash64Test {

  private static long hex(String s) {
    return Long.parseUnsignedLong(s, 16);
  }

  @Test
  void matchesReferenceVectors() throws IOException {
    byte[] data = WyHashTest.referenceData();
    int bytesChecked = 0;
    int stringsChecked = 0;
    try (BufferedReader r = new BufferedReader(new InputStreamReader(
        XxHash64Test.class.getResourceAsStream("/xxh64_vectors.txt"), StandardCharsets.UTF_8))) {
      for (String line; (line = r.readLine()) != null; ) {
        if (line.charAt(0) == 'B') {
          String[] f = line.split(" ");
          int len = Integer.parseInt(f[1]);
          long seed = hex(f[2]);
          long want = hex(f[3]);
          assertEquals(want, XxHash64.hash(data, 0, len, seed), line);
          // Unaligned offset inside a larger array.
          byte[] shifted = new byte[len + 3];
          System.arraycopy(data, 0, shifted, 3, len);
          assertEquals(want, XxHash64.hash(shifted, 3, len, seed), line);
          // Direct buffers, in both byte orders.
          ByteBuffer direct = ByteBuffer.allocateDirect(len + 5).order(ByteOrder.BIG_ENDIAN);
          direct.position(5);
          direct.put(data, 0, len);
          assertEquals(want, XxHash64.hash(direct, 5, len, seed), line);
          direct.order(ByteOrder.LITTLE_ENDIAN);
          assertEquals(want, XxHash64.hash(direct, 5, len, seed), line);
          if (seed == 0) {
            direct.position(5);
            assertEquals(want, XxHash64.hash(direct), line);
            assertEquals(5, direct.position());
          }
          bytesChecked++;
        } else {
          int sp = line.lastIndexOf(' ');
          String s = line.substring(2, sp);
          long want = hex(line.substring(sp + 1));
          assertEquals(want, XxHash64.hash(s), line);
          assertEquals(want, XxHash64.hash(s.getBytes(StandardCharsets.UTF_8)), line);
          stringsChecked++;
        }
      }
    }
    assertTrue(bytesChecked > 600);
    assertEquals(8, stringsChecked);
  }

  /**
   * hash(String) hashes ASCII strings without encoding them; it must agree with hashing the
   * UTF-8 encoding for every string, whatever the position of the first non-ASCII char.
   */
  @Test
  void stringHashEqualsHashOfUtf8() {
    char[] specials = {0x7F, 0x80, 0xA0, 0xFF, 0x100, 0x180, 0x7FF, 0x800, 0xFFFF, 0xD83D,
        0xDE00};
    java.util.SplittableRandom r = new java.util.SplittableRandom(42);
    for (int len = 0; len <= 80; len++) {
      char[] c = new char[len];
      for (int i = 0; i < len; i++) {
        c[i] = (char) (0x20 + r.nextInt(0x5F));
      }
      String ascii = new String(c);
      assertEquals(XxHash64.hash(ascii.getBytes(StandardCharsets.UTF_8)), XxHash64.hash(ascii));
      for (int pos = 0; pos < len; pos++) {
        for (char sp : specials) {
          char[] d = c.clone();
          d[pos] = sp;
          String t = new String(d);
          assertEquals(XxHash64.hash(t.getBytes(StandardCharsets.UTF_8)), XxHash64.hash(t),
              "len " + len + " pos " + pos + " char " + (int) sp);
        }
      }
    }
    String pair = "abc\uD83D\uDE00defghijklmnopqrstuvwxyz0123456789";
    assertEquals(XxHash64.hash(pair.getBytes(StandardCharsets.UTF_8)), XxHash64.hash(pair));
  }

  @Test
  void heapBufferWithOffset() {
    byte[] data = WyHashTest.referenceData();
    ByteBuffer slice = ByteBuffer.wrap(data, 7, 100).slice();
    assertEquals(XxHash64.hash(data, 7, 100), XxHash64.hash(slice));
  }

  @Test
  void rejectsBadRanges() {
    byte[] b = new byte[10];
    assertThrows(IndexOutOfBoundsException.class, () -> XxHash64.hash(b, 5, 6));
    assertThrows(IndexOutOfBoundsException.class, () -> XxHash64.hash(b, -1, 2));
    ByteBuffer d = ByteBuffer.allocateDirect(10);
    assertThrows(IndexOutOfBoundsException.class, () -> XxHash64.hash(d, 5, 6, 0));
  }
}
