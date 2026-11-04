package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.zip.CRC32C;

/**
 * Shared internals: the filter layout, the construction (peeling) algorithm and the
 * serialization header. Not part of the public API.
 */
final class Fuse {
  private Fuse() {}

  /** Arity (number of hash locations per key). */
  static final int ARITY = 3;
  /** Largest segment length, as in the C and Go reference implementations. */
  static final int MAX_SEGMENT_LENGTH = 1 << 18;
  /** Smallest segment length that a serialized filter may declare. */
  static final int MIN_SEGMENT_LENGTH = 4;
  /** Give up after this many seeds; in practice a handful suffice. */
  static final int MAX_ATTEMPTS = 100;

  // ---------------------------------------------------------------- layout

  /**
   * Filter geometry. {@code arrayLength == (segmentCount + 2) * segmentLength}, except for the
   * empty filter whose {@code arrayLength} is 0.
   */
  record Layout(int segmentLength, int segmentCount, int arrayLength) {
    int segmentLengthMask() {
      return segmentLength - 1;
    }

    long segmentCountLength() {
      return (long) segmentCount * segmentLength;
    }

    /**
     * Computes the layout for {@code size} keys, following the C/Go references, and checks
     * that the serialized filter (with {@code bits}-bit fingerprints) fits in 2 GiB.
     */
    static Layout forSize(int size, int bits) {
      if (size < 0) {
        throw new IllegalArgumentException("negative size");
      }
      if (size == 0) {
        return new Layout(MIN_SEGMENT_LENGTH, 1, 0);
      }
      if (size == 1) {
        return new Layout(MIN_SEGMENT_LENGTH, 1, (1 + ARITY - 1) * MIN_SEGMENT_LENGTH);
      }
      int shift = (int) Math.floor(Math.log(size) / Math.log(3.33) + 2.25);
      int segmentLength = shift >= 18 ? MAX_SEGMENT_LENGTH : 1 << shift;
      double sizeFactor = Math.max(1.125, 0.875 + 0.25 * Math.log(1_000_000) / Math.log(size));
      long capacity = Math.round(size * sizeFactor);
      long segments = (capacity + segmentLength - 1) / segmentLength;
      long segmentCount = segments <= ARITY - 1 ? 1 : segments - (ARITY - 1);
      long arrayLength = (segmentCount + ARITY - 1) * segmentLength;
      if (HEADER_SIZE + arrayLength * (bits / 8) > Integer.MAX_VALUE - 64) {
        throw new IllegalArgumentException("too many keys for one filter: " + size);
      }
      return new Layout(segmentLength, (int) segmentCount, (int) arrayLength);
    }
  }

  // ------------------------------------------------------------- hashing

  /** Hashes a 64-bit key with the filter seed. */
  static long hash(long key, long seed) {
    return WyHash.hash64(key, seed);
  }

  static long splitmix64(long state) {
    long z = state;
    z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
    z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
    return z ^ (z >>> 31);
  }

  private static final long SPLITMIX_GAMMA = 0x9e3779b97f4a7c15L;
  /** Initial RNG state, as in the C reference. */
  private static final long RNG_START = 0x726b2b9d438b9d4dL;

  // -------------------------------------------------------- construction

  /**
   * Output of the peeling phase: the hashes in peeling order and, for each, which of its three
   * locations was the free one. Fingerprints are assigned in reverse order.
   */
  record Peeled(long seed, int size, long[] reverseOrder, byte[] reverseH, int attempts) {}

  /**
   * Runs the binary fuse construction (hash, bucket by segment, peel) over the keys. The input
   * array is not modified. Keys are not sorted unless an attempt fails, in which case a sorted,
   * deduplicated copy is used for the remaining attempts.
   */
  static Peeled peel(long[] keys, Layout layout) {
    int size = keys.length;
    final int capacity = layout.arrayLength();
    final int segmentLength = layout.segmentLength();
    final int mask = layout.segmentLengthMask();
    final long segmentCountLength = layout.segmentCountLength();
    long[] reverseOrder = new long[size + 1];
    reverseOrder[size] = 1;
    byte[] reverseH = new byte[size];
    int[] alone = new int[capacity];
    byte[] t2count = new byte[capacity];
    long[] t2hash = new long[capacity];
    int blockBits = 1;
    while ((1 << blockBits) < layout.segmentCount()) {
      blockBits++;
    }
    final int block = 1 << blockBits;
    final int maskBlock = block - 1;
    int[] startPos = new int[block];
    boolean deduplicated = false;
    long rng = RNG_START;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      rng += SPLITMIX_GAMMA;
      final long seed = splitmix64(rng);
      if (attempt > 0) {
        if (!deduplicated) {
          keys = sortedDistinct(keys);
          deduplicated = true;
          size = keys.length;
          reverseOrder[size] = 1;
        }
        Arrays.fill(reverseOrder, 0, size, 0L);
        Arrays.fill(t2count, (byte) 0);
        Arrays.fill(t2hash, 0L);
      }
      for (int i = 0; i < block; i++) {
        startPos[i] = (int) (((long) i * size) >>> blockBits);
      }
      // Distribute the hashes by segment so that the next pass has good locality.
      for (int i = 0; i < size; i++) {
        long hash = hash(keys[i], seed);
        int segmentIndex = (int) (hash >>> (64 - blockBits));
        while (reverseOrder[startPos[segmentIndex]] != 0) {
          segmentIndex = (segmentIndex + 1) & maskBlock;
        }
        reverseOrder[startPos[segmentIndex]] = hash;
        startPos[segmentIndex]++;
      }
      boolean error = false;
      int duplicates = 0;
      for (int i = 0; i < size; i++) {
        long hash = reverseOrder[i];
        int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
        int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & mask);
        int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & mask);
        t2count[h0] += 4;
        t2hash[h0] ^= hash;
        t2count[h1] += 4;
        t2count[h1] ^= 1;
        t2hash[h1] ^= hash;
        t2count[h2] += 4;
        t2count[h2] ^= 2;
        t2hash[h2] ^= hash;
        // An exact duplicate cancels out its twin: detect it cheaply and drop it.
        if ((t2hash[h0] & t2hash[h1] & t2hash[h2]) == 0) {
          if ((t2hash[h0] == 0 && t2count[h0] == 8)
              || (t2hash[h1] == 0 && t2count[h1] == 8)
              || (t2hash[h2] == 0 && t2count[h2] == 8)) {
            duplicates++;
            t2count[h0] -= 4;
            t2hash[h0] ^= hash;
            t2count[h1] -= 4;
            t2count[h1] ^= 1;
            t2hash[h1] ^= hash;
            t2count[h2] -= 4;
            t2count[h2] ^= 2;
            t2hash[h2] ^= hash;
          }
        }
        // A count below 4 (unsigned) means the 6-bit counter overflowed.
        error |= (t2count[h0] & 0xFF) < 4 | (t2count[h1] & 0xFF) < 4 | (t2count[h2] & 0xFF) < 4;
      }
      if (error) {
        continue;
      }
      int qsize = 0;
      for (int i = 0; i < capacity; i++) {
        alone[qsize] = i;
        qsize += ((t2count[i] & 0xFF) >>> 2) == 1 ? 1 : 0;
      }
      int stackSize = 0;
      while (qsize > 0) {
        qsize--;
        int index = alone[qsize];
        if (((t2count[index] & 0xFF) >>> 2) == 1) {
          long hash = t2hash[index];
          int found = t2count[index] & 3;
          reverseH[stackSize] = (byte) found;
          reverseOrder[stackSize] = hash;
          stackSize++;
          int h0 = (int) Math.unsignedMultiplyHigh(hash, segmentCountLength);
          int h1 = (h0 + segmentLength) ^ ((int) (hash >>> 18) & mask);
          int h2 = (h0 + 2 * segmentLength) ^ ((int) hash & mask);
          int other1;
          int other2;
          if (found == 0) {
            other1 = h1;
            other2 = h2;
          } else if (found == 1) {
            other1 = h2;
            other2 = h0;
          } else {
            other1 = h0;
            other2 = h1;
          }
          int which1 = found == 2 ? 0 : found + 1;
          int which2 = found == 0 ? 2 : found - 1;
          alone[qsize] = other1;
          qsize += ((t2count[other1] & 0xFF) >>> 2) == 2 ? 1 : 0;
          t2count[other1] -= 4;
          t2count[other1] ^= which1;
          t2hash[other1] ^= hash;
          alone[qsize] = other2;
          qsize += ((t2count[other2] & 0xFF) >>> 2) == 2 ? 1 : 0;
          t2count[other2] -= 4;
          t2count[other2] ^= which2;
          t2hash[other2] ^= hash;
        }
      }
      if (stackSize + duplicates == size) {
        return new Peeled(seed, stackSize, reverseOrder, reverseH, attempt + 1);
      }
    }
    throw new IllegalStateException(
        "binary fuse construction failed after " + MAX_ATTEMPTS + " attempts");
  }

  /** Returns a sorted copy of the keys without duplicates. */
  static long[] sortedDistinct(long[] keys) {
    long[] copy = keys.clone();
    Arrays.sort(copy);
    int n = 0;
    for (int i = 0; i < copy.length; i++) {
      if (n == 0 || copy[i] != copy[n - 1]) {
        copy[n++] = copy[i];
      }
    }
    return n == copy.length ? copy : Arrays.copyOf(copy, n);
  }

  // ------------------------------------------------------- serialization

  /** Magic bytes at the start of every serialized filter: ASCII "JBFU". */
  static final int MAGIC = 0x5546424A; // little-endian 'J','B','F','U'
  static final int FORMAT_VERSION = 1;
  static final int HEADER_SIZE = 40;

  static final int OFF_VERSION = 4;
  static final int OFF_BITS = 5;
  static final int OFF_ARITY = 6;
  static final int OFF_FLAGS = 7;
  static final int OFF_SEED = 8;
  static final int OFF_KEYS = 16;
  static final int OFF_SEGMENT_LENGTH = 20;
  static final int OFF_SEGMENT_COUNT = 24;
  static final int OFF_ARRAY_LENGTH = 28;
  static final int OFF_PAYLOAD_CRC = 32;
  static final int OFF_HEADER_CRC = 36;

  /** Parsed and validated header. */
  record Header(int bits, long seed, int keyCount, Layout layout, int payloadCrc) {
    int payloadBytes() {
      return layout.arrayLength() * (bits / 8);
    }

    int totalBytes() {
      return HEADER_SIZE + payloadBytes();
    }
  }

  /**
   * Parses and validates the header at {@code buf.position()}. Checks the magic bytes, format
   * version, variant, parameters, header checksum and that the buffer holds the whole
   * fingerprint array. Does not checksum the fingerprints.
   */
  static Header readHeader(ByteBuffer buf) {
    int start = buf.position();
    if (buf.remaining() < HEADER_SIZE) {
      throw new InvalidFilterException(
          "input too short for a binary fuse filter header: " + buf.remaining() + " bytes");
    }
    ByteBuffer b = buf.duplicate().order(ByteOrder.LITTLE_ENDIAN);
    if (b.getInt(start) != MAGIC) {
      throw new InvalidFilterException("not a jbinfuse filter (bad magic bytes)");
    }
    int version = b.get(start + OFF_VERSION) & 0xFF;
    if (version != FORMAT_VERSION) {
      throw new InvalidFilterException("unsupported format version " + version
          + " (this library reads version " + FORMAT_VERSION + ")");
    }
    int headerCrc = b.getInt(start + OFF_HEADER_CRC);
    CRC32C crc = new CRC32C();
    crc.update(b.duplicate().limit(start + OFF_HEADER_CRC).position(start));
    if ((int) crc.getValue() != headerCrc) {
      throw new InvalidFilterException("header checksum mismatch (corrupt input)");
    }
    int bits = b.get(start + OFF_BITS) & 0xFF;
    if (bits != 8 && bits != 16) {
      throw new InvalidFilterException("unsupported fingerprint size: " + bits + " bits");
    }
    int arity = b.get(start + OFF_ARITY) & 0xFF;
    if (arity != ARITY) {
      throw new InvalidFilterException("unsupported arity: " + arity);
    }
    int flags = b.get(start + OFF_FLAGS) & 0xFF;
    if (flags != 0) {
      throw new InvalidFilterException("unsupported flags: " + flags);
    }
    long seed = b.getLong(start + OFF_SEED);
    long keyCount = b.getInt(start + OFF_KEYS) & 0xFFFFFFFFL;
    long segmentLength = b.getInt(start + OFF_SEGMENT_LENGTH) & 0xFFFFFFFFL;
    long segmentCount = b.getInt(start + OFF_SEGMENT_COUNT) & 0xFFFFFFFFL;
    long arrayLength = b.getInt(start + OFF_ARRAY_LENGTH) & 0xFFFFFFFFL;
    if (segmentLength < MIN_SEGMENT_LENGTH || segmentLength > MAX_SEGMENT_LENGTH
        || Long.bitCount(segmentLength) != 1) {
      throw new InvalidFilterException("invalid segment length: " + segmentLength);
    }
    if (segmentCount < 1) {
      throw new InvalidFilterException("invalid segment count: " + segmentCount);
    }
    long expected = keyCount == 0 ? 0 : (segmentCount + ARITY - 1) * segmentLength;
    if (arrayLength != expected) {
      throw new InvalidFilterException("inconsistent array length " + arrayLength
          + " (expected " + expected + ")");
    }
    if (keyCount > arrayLength) {
      throw new InvalidFilterException("key count " + keyCount + " exceeds array length");
    }
    long payload = arrayLength * (bits / 8);
    if (HEADER_SIZE + payload > buf.remaining()) {
      throw new InvalidFilterException("truncated input: need " + (HEADER_SIZE + payload)
          + " bytes, have " + buf.remaining());
    }
    return new Header(bits, seed, (int) keyCount,
        new Layout((int) segmentLength, (int) segmentCount, (int) arrayLength),
        b.getInt(start + OFF_PAYLOAD_CRC));
  }

  /** Verifies the fingerprint checksum of a filter whose header was read at {@code start}. */
  static void verifyPayload(ByteBuffer buf, Header h) {
    int from = buf.position() + HEADER_SIZE;
    if (crc32c(buf, from, h.payloadBytes()) != h.payloadCrc()) {
      throw new InvalidFilterException("fingerprint checksum mismatch (corrupt input)");
    }
  }

  static int crc32c(ByteBuffer buf, int from, int length) {
    CRC32C crc = new CRC32C();
    crc.update(buf.duplicate().limit(from + length).position(from));
    return (int) crc.getValue();
  }

  /**
   * Writes the header at {@code out}'s position; the fingerprints must already have been
   * written right after it. Advances {@code out}'s position past the whole filter.
   */
  static void finishWrite(ByteBuffer out, int bits, long seed, int keyCount, Layout layout) {
    int start = out.position();
    ByteBuffer b = out.duplicate().order(ByteOrder.LITTLE_ENDIAN);
    int payloadBytes = layout.arrayLength() * (bits / 8);
    b.putInt(start, MAGIC);
    b.put(start + OFF_VERSION, (byte) FORMAT_VERSION);
    b.put(start + OFF_BITS, (byte) bits);
    b.put(start + OFF_ARITY, (byte) ARITY);
    b.put(start + OFF_FLAGS, (byte) 0);
    b.putLong(start + OFF_SEED, seed);
    b.putInt(start + OFF_KEYS, keyCount);
    b.putInt(start + OFF_SEGMENT_LENGTH, layout.segmentLength());
    b.putInt(start + OFF_SEGMENT_COUNT, layout.segmentCount());
    b.putInt(start + OFF_ARRAY_LENGTH, layout.arrayLength());
    b.putInt(start + OFF_PAYLOAD_CRC, crc32c(b, start + HEADER_SIZE, payloadBytes));
    b.putInt(start + OFF_HEADER_CRC, crc32c(b, start, OFF_HEADER_CRC));
    out.position(start + HEADER_SIZE + payloadBytes);
  }

  static void checkSpace(ByteBuffer out, int bytes) {
    if (out.remaining() < bytes) {
      throw new java.nio.BufferOverflowException();
    }
  }

  /** Hashes byte-array keys to 64-bit keys with {@link WyHash#hash(byte[])}. */
  static long[] hashAll(java.util.Collection<byte[]> keys) {
    long[] hashes = new long[keys.size()];
    int i = 0;
    for (byte[] key : keys) {
      hashes[i++] = WyHash.hash(key);
    }
    if (i != hashes.length) {
      throw new java.util.ConcurrentModificationException();
    }
    return hashes;
  }
}
