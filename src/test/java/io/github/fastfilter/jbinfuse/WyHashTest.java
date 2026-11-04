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
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Checks WyHash against vectors produced by the reference C implementation
 * (tools/wyhash_vectors.c, wyhash final version 4.3).
 */
class WyHashTest {

  /** Same LCG as tools/wyhash_vectors.c. */
  static byte[] referenceData() {
    byte[] data = new byte[1024];
    long state = 0x9E3779B97F4A7C15L;
    for (int i = 0; i < data.length; i++) {
      state = state * 6364136223846793005L + 1442695040888963407L;
      data[i] = (byte) (state >>> 56);
    }
    return data;
  }

  static List<String> vectors() throws IOException {
    List<String> lines = new ArrayList<>();
    try (BufferedReader r = new BufferedReader(new InputStreamReader(
        WyHashTest.class.getResourceAsStream("/wyhash_vectors.txt"), StandardCharsets.UTF_8))) {
      for (String line; (line = r.readLine()) != null; ) {
        lines.add(line);
      }
    }
    return lines;
  }

  private static long hex(String s) {
    return Long.parseUnsignedLong(s, 16);
  }

  @Test
  void matchesReferenceVectors() throws IOException {
    byte[] data = referenceData();
    int bytesChecked = 0;
    int stringsChecked = 0;
    int mixChecked = 0;
    for (String line : vectors()) {
      switch (line.charAt(0)) {
        case 'B' -> {
          String[] f = line.split(" ");
          int len = Integer.parseInt(f[1]);
          long seed = hex(f[2]);
          long expected = hex(f[3]);
          assertEquals(expected, WyHash.hash(data, 0, len, seed), line);
          // Same bytes at an unaligned offset of a larger array.
          byte[] shifted = new byte[len + 7];
          System.arraycopy(data, 0, shifted, 3, len);
          assertEquals(expected, WyHash.hash(shifted, 3, len, seed), line);
          // Heap and direct buffers, both byte orders.
          for (ByteOrder order : new ByteOrder[] {ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN}) {
            ByteBuffer heap = ByteBuffer.wrap(shifted).order(order);
            assertEquals(expected, WyHash.hash(heap, 3, len, seed), line);
            ByteBuffer direct = ByteBuffer.allocateDirect(len + 7).order(order);
            direct.put(shifted).flip();
            assertEquals(expected, WyHash.hash(direct, 3, len, seed), line);
            if (seed == 0) {
              direct.position(3).limit(3 + len);
              assertEquals(expected, WyHash.hash(direct), line);
              assertEquals(3, direct.position());
            }
          }
          if (seed == 0) {
            assertEquals(expected, WyHash.hash(data, 0, len), line);
            byte[] exact = java.util.Arrays.copyOf(data, len);
            assertEquals(expected, WyHash.hash(exact), line);
          }
          bytesChecked++;
        }
        case 'S' -> {
          int last = line.lastIndexOf(' ');
          String s = line.substring(2, last);
          long expected = hex(line.substring(last + 1));
          assertEquals(expected, WyHash.hash(s.getBytes(StandardCharsets.US_ASCII)), line);
          stringsChecked++;
        }
        case 'M' -> {
          String[] f = line.split(" ");
          assertEquals(hex(f[3]), WyHash.hash64(hex(f[1]), hex(f[2])), line);
          mixChecked++;
        }
        default -> throw new AssertionError("bad vector line: " + line);
      }
    }
    assertEquals(5 * 306, bytesChecked);
    assertTrue(stringsChecked >= 9);
    assertTrue(mixChecked >= 66);
  }

  @Test
  void rejectsOutOfBoundsRanges() {
    byte[] data = new byte[10];
    assertThrows(IndexOutOfBoundsException.class, () -> WyHash.hash(data, 5, 6));
    assertThrows(IndexOutOfBoundsException.class, () -> WyHash.hash(data, -1, 2));
    assertThrows(IndexOutOfBoundsException.class,
        () -> WyHash.hash(ByteBuffer.wrap(data), 8, 3, 0));
  }
}
