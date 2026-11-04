package io.github.fastfilter.jbinfuse;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * A Java implementation of XXH64, the 64-bit hash of xxHash by Yann Collet
 * (<a href="https://github.com/Cyan4973/xxHash">github.com/Cyan4973/xxHash</a>).
 *
 * <p>The results are bit-for-bit identical to the reference C function
 * {@code XXH64(input, length, seed)}, and so to Go's {@code xxhash.Sum64} (seed 0). This is
 * the key hash of the constant maps ({@link ConstMap}, {@link VerifiedConstMap},
 * {@link PairedVerifiedConstMap}), which must agree with the Go, Rust and C implementations
 * for their files to be interchangeable. Bytes are always read as little-endian, regardless
 * of the platform or of the byte order of a {@link ByteBuffer}.
 *
 * <p>This class is stateless and thread-safe.
 */
public final class XxHash64 {
  private static final long P1 = 0x9E3779B185EBCA87L;
  private static final long P2 = 0xC2B2AE3D27D4EB4FL;
  private static final long P3 = 0x165667B19E3779F9L;
  private static final long P4 = 0x85EBCA77C2B2AE63L;
  private static final long P5 = 0x27D4EB2F165667C5L;

  private static final VarHandle LONG_LE =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle INT_LE =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

  private XxHash64() {}

  /**
   * Hashes the UTF-8 encoding of a string, with seed 0. This is how the constant maps hash
   * {@code String} keys, and equals Go's {@code xxhash.Sum64String(s)}.
   *
   * @param s the string to hash
   * @return the 64-bit hash
   */
  public static long hash(String s) {
    final int len = s.length();
    // Fast path for ASCII strings, whose UTF-8 encoding is one byte per char: hash the chars
    // directly rather than allocate the encoding. Any other char sends us to the encoder.
    int p = 0;
    long h;
    if (len >= 32) {
      long v1 = P1 + P2;
      long v2 = P2;
      long v3 = 0;
      long v4 = -P1;
      final int limit = len - 32;
      do {
        long a = ascii8(s, p);
        long b = ascii8(s, p + 8);
        long c = ascii8(s, p + 16);
        long d = ascii8(s, p + 24);
        if (((a | b | c | d) & 0x8080808080808080L) != 0) {
          return hashEncoded(s);
        }
        v1 = round(v1, a);
        v2 = round(v2, b);
        v3 = round(v3, c);
        v4 = round(v4, d);
        p += 32;
      } while (p <= limit);
      h = Long.rotateLeft(v1, 1) + Long.rotateLeft(v2, 7) + Long.rotateLeft(v3, 12)
          + Long.rotateLeft(v4, 18);
      h = mergeRound(h, v1);
      h = mergeRound(h, v2);
      h = mergeRound(h, v3);
      h = mergeRound(h, v4);
    } else {
      h = P5;
    }
    h += len;
    while (p + 8 <= len) {
      long a = ascii8(s, p);
      if ((a & 0x8080808080808080L) != 0) {
        return hashEncoded(s);
      }
      h ^= round(0, a);
      h = Long.rotateLeft(h, 27) * P1 + P4;
      p += 8;
    }
    if (p + 4 <= len) {
      long a = asciiWord(s, p, 4);
      if ((a & 0x80808080L) != 0) {
        return hashEncoded(s);
      }
      h ^= a * P1;
      h = Long.rotateLeft(h, 23) * P2 + P3;
      p += 4;
    }
    while (p < len) {
      char c = s.charAt(p);
      if (c >= 0x80) {
        return hashEncoded(s);
      }
      h ^= c * P5;
      h = Long.rotateLeft(h, 11) * P1;
      p++;
    }
    return avalanche(h);
  }

  /**
   * The little-endian word of {@code n} chars from {@code p}, each char that is not ASCII
   * replaced by 0x80 so that it shows in the caller's {@code 0x80} mask.
   */
  private static long asciiWord(String s, int p, int n) {
    long w = 0;
    for (int i = n - 1; i >= 0; i--) {
      char c = s.charAt(p + i);
      w = (w << 8) | (c < 0x80 ? c : 0x80);
    }
    return w;
  }

  private static long ascii8(String s, int p) {
    return asciiWord(s, p, 8);
  }

  private static long hashEncoded(String s) {
    byte[] b = s.getBytes(StandardCharsets.UTF_8);
    return hash(b, 0, b.length, 0);
  }

  /**
   * Hashes a whole byte array with seed 0.
   *
   * @param data the bytes to hash
   * @return the 64-bit hash
   */
  public static long hash(byte[] data) {
    return hash(data, 0, data.length, 0);
  }

  /**
   * Hashes {@code len} bytes of {@code data} starting at {@code off}, with seed 0.
   *
   * @param data the array holding the bytes
   * @param off the index of the first byte to hash
   * @param len the number of bytes to hash
   * @return the 64-bit hash
   * @throws IndexOutOfBoundsException if the range is not within {@code data}
   */
  public static long hash(byte[] data, int off, int len) {
    return hash(data, off, len, 0);
  }

  private static long round(long acc, long input) {
    acc += input * P2;
    acc = Long.rotateLeft(acc, 31);
    return acc * P1;
  }

  private static long mergeRound(long acc, long val) {
    acc ^= round(0, val);
    return acc * P1 + P4;
  }

  private static long avalanche(long h) {
    h ^= h >>> 33;
    h *= P2;
    h ^= h >>> 29;
    h *= P3;
    h ^= h >>> 32;
    return h;
  }

  private static long r8(byte[] p, int i) {
    return (long) LONG_LE.get(p, i);
  }

  private static long r4(byte[] p, int i) {
    return ((int) INT_LE.get(p, i)) & 0xFFFFFFFFL;
  }

  /**
   * Hashes {@code len} bytes of {@code data} starting at {@code off}, with the given seed.
   *
   * @param data the array holding the bytes
   * @param off the index of the first byte to hash
   * @param len the number of bytes to hash
   * @param seed the seed
   * @return the 64-bit hash, equal to the C reference {@code XXH64(data + off, len, seed)}
   * @throws IndexOutOfBoundsException if the range is not within {@code data}
   */
  public static long hash(byte[] data, int off, int len, long seed) {
    Objects.checkFromIndexSize(off, len, data.length);
    int p = off;
    final int end = off + len;
    long h;
    if (len >= 32) {
      long v1 = seed + P1 + P2;
      long v2 = seed + P2;
      long v3 = seed;
      long v4 = seed - P1;
      final int limit = end - 32;
      do {
        v1 = round(v1, r8(data, p));
        v2 = round(v2, r8(data, p + 8));
        v3 = round(v3, r8(data, p + 16));
        v4 = round(v4, r8(data, p + 24));
        p += 32;
      } while (p <= limit);
      h = Long.rotateLeft(v1, 1) + Long.rotateLeft(v2, 7) + Long.rotateLeft(v3, 12)
          + Long.rotateLeft(v4, 18);
      h = mergeRound(h, v1);
      h = mergeRound(h, v2);
      h = mergeRound(h, v3);
      h = mergeRound(h, v4);
    } else {
      h = seed + P5;
    }
    h += len;
    while (p + 8 <= end) {
      h ^= round(0, r8(data, p));
      h = Long.rotateLeft(h, 27) * P1 + P4;
      p += 8;
    }
    if (p + 4 <= end) {
      h ^= r4(data, p) * P1;
      h = Long.rotateLeft(h, 23) * P2 + P3;
      p += 4;
    }
    while (p < end) {
      h ^= (data[p] & 0xFFL) * P5;
      h = Long.rotateLeft(h, 11) * P1;
      p++;
    }
    return avalanche(h);
  }

  /**
   * Hashes the bytes of a buffer from its position to its limit, with seed 0. The buffer's
   * position, limit and byte order are not changed.
   *
   * @param buf the buffer
   * @return the 64-bit hash
   */
  public static long hash(ByteBuffer buf) {
    return hash(buf, buf.position(), buf.remaining(), 0);
  }

  private static long r8(ByteBuffer p, int i, boolean swap) {
    long v = p.getLong(i);
    return swap ? Long.reverseBytes(v) : v;
  }

  private static long r4(ByteBuffer p, int i, boolean swap) {
    int v = p.getInt(i);
    return (swap ? Integer.reverseBytes(v) : v) & 0xFFFFFFFFL;
  }

  /**
   * Hashes {@code len} bytes of a buffer starting at absolute index {@code off}, with the
   * given seed. The buffer's position, limit and byte order are not changed.
   *
   * @param buf the buffer
   * @param off the absolute index of the first byte to hash
   * @param len the number of bytes to hash
   * @param seed the seed
   * @return the 64-bit hash, equal to {@link #hash(byte[], int, int, long)} on the same bytes
   * @throws IndexOutOfBoundsException if the range is not within the buffer's limit
   */
  public static long hash(ByteBuffer buf, int off, int len, long seed) {
    if (buf.hasArray()) {
      return hash(buf.array(), buf.arrayOffset() + Objects.checkFromIndexSize(off, len,
          buf.limit()), len, seed);
    }
    Objects.checkFromIndexSize(off, len, buf.limit());
    final boolean swap = buf.order() != ByteOrder.LITTLE_ENDIAN;
    int p = off;
    final int end = off + len;
    long h;
    if (len >= 32) {
      long v1 = seed + P1 + P2;
      long v2 = seed + P2;
      long v3 = seed;
      long v4 = seed - P1;
      final int limit = end - 32;
      do {
        v1 = round(v1, r8(buf, p, swap));
        v2 = round(v2, r8(buf, p + 8, swap));
        v3 = round(v3, r8(buf, p + 16, swap));
        v4 = round(v4, r8(buf, p + 24, swap));
        p += 32;
      } while (p <= limit);
      h = Long.rotateLeft(v1, 1) + Long.rotateLeft(v2, 7) + Long.rotateLeft(v3, 12)
          + Long.rotateLeft(v4, 18);
      h = mergeRound(h, v1);
      h = mergeRound(h, v2);
      h = mergeRound(h, v3);
      h = mergeRound(h, v4);
    } else {
      h = seed + P5;
    }
    h += len;
    while (p + 8 <= end) {
      h ^= round(0, r8(buf, p, swap));
      h = Long.rotateLeft(h, 27) * P1 + P4;
      p += 8;
    }
    if (p + 4 <= end) {
      h ^= r4(buf, p, swap) * P1;
      h = Long.rotateLeft(h, 23) * P2 + P3;
      p += 4;
    }
    while (p < end) {
      h ^= (buf.get(p) & 0xFFL) * P5;
      h = Long.rotateLeft(h, 11) * P1;
      p++;
    }
    return avalanche(h);
  }
}
