package io.github.fastfilter.jbinfuse;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * A Java implementation of wyhash, final version 4.3, by Wang Yi
 * (<a href="https://github.com/wangyi-fudan/wyhash">github.com/wangyi-fudan/wyhash</a>),
 * with the default secret.
 *
 * <p>The results are bit-for-bit identical to the reference C function
 * {@code wyhash(key, len, seed, _wyp)} (with the default {@code WYHASH_CONDOM=1}
 * and {@code WYHASH_32BIT_MUM=0}), and {@link #hash64(long, long)} is identical to the
 * reference {@code wyhash64(a, b)}. Bytes are always read as little-endian, regardless of
 * the platform or of the byte order of a {@link ByteBuffer}, so hashes are portable.
 *
 * <p>This class is stateless and thread-safe.
 */
public final class WyHash {
  private static final long P0 = 0x2d358dccaa6c78a5L;
  private static final long P1 = 0x8bb84b93962eacc9L;
  private static final long P2 = 0x4b33a62ed433d4a3L;
  private static final long P3 = 0x4d5a2da51de1aa47L;

  private static final VarHandle LONG_LE =
      MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);
  private static final VarHandle INT_LE =
      MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.LITTLE_ENDIAN);

  private WyHash() {}

  /** The "MUM" mix: the low 64 bits of the 128-bit product xor the high 64 bits. */
  private static long mix(long a, long b) {
    return (a * b) ^ Math.unsignedMultiplyHigh(a, b);
  }

  private static long r8(byte[] p, int i) {
    return (long) LONG_LE.get(p, i);
  }

  private static long r4(byte[] p, int i) {
    return ((int) INT_LE.get(p, i)) & 0xFFFFFFFFL;
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

  /**
   * Hashes {@code len} bytes of {@code data} starting at {@code off}, with the given seed.
   *
   * @param data the array holding the bytes
   * @param off the index of the first byte to hash
   * @param len the number of bytes to hash
   * @param seed the seed
   * @return the 64-bit hash, equal to the C reference {@code wyhash(data + off, len, seed, _wyp)}
   * @throws IndexOutOfBoundsException if the range is not within {@code data}
   */
  public static long hash(byte[] data, int off, int len, long seed) {
    Objects.checkFromIndexSize(off, len, data.length);
    seed ^= mix(seed ^ P0, P1);
    long a;
    long b;
    if (len <= 16) {
      if (len >= 4) {
        int d = (len >>> 3) << 2;
        a = (r4(data, off) << 32) | r4(data, off + d);
        b = (r4(data, off + len - 4) << 32) | r4(data, off + len - 4 - d);
      } else if (len > 0) {
        a = ((data[off] & 0xFFL) << 16) | ((data[off + (len >>> 1)] & 0xFFL) << 8)
            | (data[off + len - 1] & 0xFFL);
        b = 0;
      } else {
        a = 0;
        b = 0;
      }
    } else {
      int p = off;
      int i = len;
      if (i >= 48) {
        long see1 = seed;
        long see2 = seed;
        do {
          seed = mix(r8(data, p) ^ P1, r8(data, p + 8) ^ seed);
          see1 = mix(r8(data, p + 16) ^ P2, r8(data, p + 24) ^ see1);
          see2 = mix(r8(data, p + 32) ^ P3, r8(data, p + 40) ^ see2);
          p += 48;
          i -= 48;
        } while (i >= 48);
        seed ^= see1 ^ see2;
      }
      while (i > 16) {
        seed = mix(r8(data, p) ^ P1, r8(data, p + 8) ^ seed);
        i -= 16;
        p += 16;
      }
      a = r8(data, p + i - 16);
      b = r8(data, p + i - 8);
    }
    return finish(a, b, seed, len);
  }

  /**
   * Hashes the remaining bytes of a buffer (from its position to its limit) with seed 0.
   * The buffer's position, limit and byte order are not modified.
   *
   * @param data the buffer (heap, direct or memory-mapped)
   * @return the 64-bit hash, equal to {@link #hash(byte[])} of the same bytes
   */
  public static long hash(ByteBuffer data) {
    return hash(data, data.position(), data.remaining(), 0);
  }

  /**
   * Hashes {@code len} bytes of a buffer starting at absolute index {@code off}, with the
   * given seed. The buffer's position, limit and byte order are not modified.
   *
   * @param data the buffer (heap, direct or memory-mapped)
   * @param off the absolute index of the first byte to hash
   * @param len the number of bytes to hash
   * @param seed the seed
   * @return the 64-bit hash, equal to {@link #hash(byte[], int, int, long)} of the same bytes
   * @throws IndexOutOfBoundsException if the range is not within the buffer's limit
   */
  public static long hash(ByteBuffer data, int off, int len, long seed) {
    Objects.checkFromIndexSize(off, len, data.limit());
    final boolean swap = data.order() != ByteOrder.LITTLE_ENDIAN;
    seed ^= mix(seed ^ P0, P1);
    long a;
    long b;
    if (len <= 16) {
      if (len >= 4) {
        int d = (len >>> 3) << 2;
        a = (r4(data, off, swap) << 32) | r4(data, off + d, swap);
        b = (r4(data, off + len - 4, swap) << 32) | r4(data, off + len - 4 - d, swap);
      } else if (len > 0) {
        a = ((data.get(off) & 0xFFL) << 16) | ((data.get(off + (len >>> 1)) & 0xFFL) << 8)
            | (data.get(off + len - 1) & 0xFFL);
        b = 0;
      } else {
        a = 0;
        b = 0;
      }
    } else {
      int p = off;
      int i = len;
      if (i >= 48) {
        long see1 = seed;
        long see2 = seed;
        do {
          seed = mix(r8(data, p, swap) ^ P1, r8(data, p + 8, swap) ^ seed);
          see1 = mix(r8(data, p + 16, swap) ^ P2, r8(data, p + 24, swap) ^ see1);
          see2 = mix(r8(data, p + 32, swap) ^ P3, r8(data, p + 40, swap) ^ see2);
          p += 48;
          i -= 48;
        } while (i >= 48);
        seed ^= see1 ^ see2;
      }
      while (i > 16) {
        seed = mix(r8(data, p, swap) ^ P1, r8(data, p + 8, swap) ^ seed);
        i -= 16;
        p += 16;
      }
      a = r8(data, p + i - 16, swap);
      b = r8(data, p + i - 8, swap);
    }
    return finish(a, b, seed, len);
  }

  private static long finish(long a, long b, long seed, int len) {
    a ^= P1;
    b ^= seed;
    long lo = a * b;
    long hi = Math.unsignedMultiplyHigh(a, b);
    return mix(lo ^ P0 ^ len, hi ^ P1);
  }

  /**
   * Mixes two 64-bit values into one; identical to the reference C {@code wyhash64(a, b)}.
   * Binary fuse filters use it to hash 64-bit keys with the filter's seed.
   *
   * @param a the first value
   * @param b the second value
   * @return the 64-bit hash
   */
  public static long hash64(long a, long b) {
    a ^= P0;
    b ^= P1;
    long lo = a * b;
    long hi = Math.unsignedMultiplyHigh(a, b);
    return mix(lo ^ P0, hi ^ P1);
  }
}
