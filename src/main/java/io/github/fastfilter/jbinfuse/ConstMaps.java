package io.github.fastfilter.jbinfuse;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Construction and serialization shared by {@link ConstMap}, {@link VerifiedConstMap} and
 * {@link PairedVerifiedConstMap}.
 *
 * <p>Everything here follows <a href="https://github.com/lemire/constmap">constmap</a> (Go)
 * exactly: the key hash (XXH64, seed 0), the mixing ({@code murmur64(hash + seed)}), the seed
 * sequence (splitmix64 from 1), the segment parameters, the retry schedule and the peeling
 * order. For the same keys and values the three maps therefore hold the same words as the Go,
 * Rust (<a href="https://github.com/lemire/rsconstmap">rsconstmap</a>) and C/Python
 * (<a href="https://github.com/lemire/fastconstmap">fastconstmap</a>) implementations, and
 * serialize to the same bytes as Go and Rust.
 */
final class ConstMaps {
  private ConstMaps() {}

  /** Returned by verified lookups for keys that are not in the map. */
  static final long NOT_FOUND = -1L;

  static final int MAX_SEGMENT_LENGTH = 262144;
  static final int MAX_ITERATIONS = 100;

  /** Keys per block in the batched lookups ({@code getMany}). */
  static final int BLOCK = 8;

  /**
   * Largest array length we build or load: a paired map holds two words per position in one
   * Java array.
   */
  static final int MAX_ARRAY_LENGTH = (Integer.MAX_VALUE - 16) / 2;

  // ---------------------------------------------------------------------------------------
  // Hashing.

  static long murmur64(long h) {
    h ^= h >>> 33;
    h *= 0xff51afd7ed558ccdL;
    h ^= h >>> 33;
    h *= 0xc4ceb9fe1a85ec53L;
    h ^= h >>> 33;
    return h;
  }

  static long mixsplit(long key, long seed) {
    return murmur64(key + seed);
  }

  /** The verification word derived from a mixed hash. */
  static long fingerprint(long hash) {
    return hash ^ (hash >>> 32);
  }

  static long[] hashStrings(List<String> keys) {
    long[] h = new long[keys.size()];
    int i = 0;
    for (String k : keys) {
      h[i++] = XxHash64.hash(k);
    }
    return h;
  }

  static long[] hashBytes(List<byte[]> keys) {
    long[] h = new long[keys.size()];
    int i = 0;
    for (byte[] k : keys) {
      h[i++] = XxHash64.hash(k);
    }
    return h;
  }

  // ---------------------------------------------------------------------------------------
  // Layout.

  /**
   * The parameters of a map. Positions are {@code h0 = mulhi(hash, segmentCount *
   * segmentLength)}, {@code h1 = (h0 + segmentLength) ^ ((hash >>> 18) & mask)} and {@code h2 =
   * (h0 + 2 * segmentLength) ^ (hash & mask)}, all below {@code arrayLength = (segmentCount +
   * 2) * segmentLength}.
   */
  record Params(long seed, int segmentLength, int segmentCount, int arrayLength) {
    static final Params EMPTY = new Params(0, 0, 0, 0);

    int segmentLengthMask() {
      return segmentLength - 1;
    }

    long segmentCountLength() {
      return (long) segmentCount * segmentLength;
    }
  }

  static int calculateSegmentLength(int size) {
    if (size == 0) {
      return 4;
    }
    return 1 << (int) Math.floor(Math.log(size) / Math.log(3.33) + 2.25);
  }

  static double calculateSizeFactor(int size) {
    return Math.max(1.125, 0.875 + 0.25 * Math.log(1000000) / Math.log(size));
  }

  // ---------------------------------------------------------------------------------------
  // Construction.

  /**
   * The outcome of peeling: the seed and parameters that worked, and for each stack entry
   * (to be assigned in reverse) the mixed hash, which of its three positions it owns, and the
   * index of the key in the caller's arrays.
   */
  record Peeled(Params params, long[] order, byte[] which, int[] keyIndex) {}

  static void checkLengths(int keys, int values) {
    if (keys != values) {
      throw new IllegalArgumentException(
          "keys and values must have equal length (" + keys + " vs " + values + ")");
    }
  }

  /**
   * Finds a seed and an assignment order for keys with the given XXH64 hashes. A port of the
   * construction loop of constmap's {@code New}; where the Go code recovers each key's value
   * through a map from mixed hash to value, this keeps the XOR of the key indices in each
   * cell next to the XOR of their hashes, so a singleton cell names its key directly. The
   * peeling, and so the result, is the same.
   *
   * @param hashes the XXH64 key hashes; must not be empty
   */
  static Peeled peel(long[] hashes) {
    final int size = hashes.length;
    int segmentLength = Math.min(calculateSegmentLength(size), MAX_SEGMENT_LENGTH);
    long cap0 = 0;
    if (size > 1) {
      cap0 = Math.round(size * calculateSizeFactor(size));
    }
    long totalSegmentCount = Math.max(3, (cap0 + segmentLength - 1) / segmentLength);
    long arrayLengthLong = totalSegmentCount * segmentLength;
    if (arrayLengthLong > MAX_ARRAY_LENGTH) {
      throw new IllegalArgumentException("too many keys for one map: " + size);
    }
    final int capacity = (int) arrayLengthLong;
    int segmentCount = (int) totalSegmentCount - 2;

    long rngcounter = 1;
    rngcounter += 0x9E3779B97F4A7C15L;
    long seed = splitmix64Value(rngcounter);

    final int[] alone = new int[capacity];
    final byte[] t2count = new byte[capacity];
    final long[] t2hash = new long[capacity];
    final int[] t2index = new int[capacity];
    final byte[] reverseH = new byte[size];
    final long[] reverseOrder = new long[size + 1];
    final int[] reverseIndex = new int[size];
    final int[] bucketIndex = new int[size];
    reverseOrder[size] = 1;

    for (int iterations = 0; ; iterations++) {
      if (iterations > MAX_ITERATIONS) {
        throw new IllegalArgumentException("failed to construct map, possible duplicate keys");
      }
      if (size > 4 && size < 1_000_000) {
        switch (iterations % 4) {
          case 2 -> {
            segmentLength /= 2;
            segmentCount = segmentCount * 2 + 2;
          }
          case 3 -> {
            segmentLength *= 2;
            segmentCount = segmentCount / 2 - 1;
          }
          default -> { }
        }
      }
      final int segLen = segmentLength;
      final int mask = segLen - 1;
      final long scl = (long) segmentCount * segLen;

      int blockBits = 1;
      while ((1L << blockBits) < segmentCount) {
        blockBits++;
      }
      final int[] startPos = new int[1 << blockBits];
      for (int i = 0; i < startPos.length; i++) {
        startPos[i] = (int) (((long) i * size) >>> blockBits);
      }
      final int blockMask = (1 << blockBits) - 1;
      for (int k = 0; k < size; k++) {
        long hash = mixsplit(hashes[k], seed);
        int segmentIndex = (int) (hash >>> (64 - blockBits));
        while (reverseOrder[startPos[segmentIndex]] != 0) {
          segmentIndex = (segmentIndex + 1) & blockMask;
        }
        reverseOrder[startPos[segmentIndex]] = hash;
        bucketIndex[startPos[segmentIndex]] = k;
        startPos[segmentIndex]++;
      }

      boolean hasError = false;
      for (int i = 0; i < size; i++) {
        long hash = reverseOrder[i];
        int key = bucketIndex[i];
        int i1 = (int) Math.unsignedMultiplyHigh(hash, scl);
        int i2 = (i1 + segLen) ^ ((int) (hash >>> 18) & mask);
        int i3 = (i1 + 2 * segLen) ^ ((int) hash & mask);
        t2count[i1] += 4;
        t2hash[i1] ^= hash;
        t2index[i1] ^= key;
        t2count[i2] = (byte) ((t2count[i2] + 4) ^ 1);
        t2hash[i2] ^= hash;
        t2index[i2] ^= key;
        t2count[i3] = (byte) ((t2count[i3] + 4) ^ 2);
        t2hash[i3] ^= hash;
        t2index[i3] ^= key;
        if ((t2hash[i1] & t2hash[i2] & t2hash[i3]) == 0) {
          if ((t2hash[i1] == 0 && t2count[i1] == 8)
              || (t2hash[i2] == 0 && t2count[i2] == 8)
              || (t2hash[i3] == 0 && t2count[i3] == 8)) {
            throw new IllegalArgumentException("duplicate key hash detected");
          }
        }
        if ((t2count[i1] & 0xFF) < 4 || (t2count[i2] & 0xFF) < 4
            || (t2count[i3] & 0xFF) < 4) {
          hasError = true;
        }
      }

      int stacksize = 0;
      if (!hasError) {
        int qsize = 0;
        for (int i = 0; i < capacity; i++) {
          alone[qsize] = i;
          if (((t2count[i] & 0xFF) >>> 2) == 1) {
            qsize++;
          }
        }
        final int segLenToMinusSegLenX2 = segLen ^ (-(2 * segLen));
        while (qsize > 0) {
          qsize--;
          int index = alone[qsize];
          if (((t2count[index] & 0xFF) >>> 2) == 1) {
            long hash = t2hash[index];
            int found = t2count[index] & 3;
            reverseH[stacksize] = (byte) found;
            reverseOrder[stacksize] = hash;
            int key = t2index[index];
            reverseIndex[stacksize] = key;
            stacksize++;

            int h01 = (int) (hash >>> 18) & mask;
            int h02 = (int) hash & mask;
            int is0 = -(((found - 1) & 0xFF) >>> 7);
            int is1 = -(found & 1);
            int is2 = -(found >>> 1);
            int other1 = index + (segLen ^ (segLenToMinusSegLenX2 & is2));
            int other2 = index - (segLen ^ (segLenToMinusSegLenX2 & is0));
            other1 ^= (h01 & ~is2) ^ (h02 & ~is0);
            other2 ^= (h01 & ~is0) ^ (h02 & ~is1);
            int f1 = (is0 & 1) | (is1 & 2);
            int f2 = (is0 & 2) | (is2 & 1);

            alone[qsize] = other1;
            if (((t2count[other1] & 0xFF) >>> 2) == 2) {
              qsize++;
            }
            t2count[other1] = (byte) ((t2count[other1] - 4) ^ f1);
            t2hash[other1] ^= hash;
            t2index[other1] ^= key;

            alone[qsize] = other2;
            if (((t2count[other2] & 0xFF) >>> 2) == 2) {
              qsize++;
            }
            t2count[other2] = (byte) ((t2count[other2] - 4) ^ f2);
            t2hash[other2] ^= hash;
            t2index[other2] ^= key;
          }
        }
      }
      if (stacksize == size) {
        Params params = new Params(seed, segLen, segmentCount, capacity);
        return new Peeled(params, Arrays.copyOf(reverseOrder, size), reverseH, reverseIndex);
      }
      Arrays.fill(reverseOrder, 0, size, 0);
      Arrays.fill(t2count, (byte) 0);
      Arrays.fill(t2hash, 0);
      Arrays.fill(t2index, 0);
      rngcounter += 0x9E3779B97F4A7C15L;
      seed = splitmix64Value(rngcounter);
    }
  }

  /** The output of splitmix64 for an already-advanced state. */
  private static long splitmix64Value(long z) {
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
    return z ^ (z >>> 31);
  }

  /**
   * Fills {@code data} (and, if not null, {@code checks}) so that the three positions of each
   * key XOR to its value (and to its fingerprint).
   */
  static void assign(Peeled p, long[] values, long[] data, long[] checks) {
    final Params params = p.params();
    final int segLen = params.segmentLength();
    final int mask = params.segmentLengthMask();
    final long scl = params.segmentCountLength();
    final long[] order = p.order();
    final byte[] which = p.which();
    final int[] keyIndex = p.keyIndex();
    for (int i = order.length - 1; i >= 0; i--) {
      long hash = order[i];
      int h0 = (int) Math.unsignedMultiplyHigh(hash, scl);
      int h1 = (h0 + segLen) ^ ((int) (hash >>> 18) & mask);
      int h2 = (h0 + 2 * segLen) ^ ((int) hash & mask);
      int a;
      int b;
      int c;
      switch (which[i]) {
        case 0 -> {
          a = h0;
          b = h1;
          c = h2;
        }
        case 1 -> {
          a = h1;
          b = h2;
          c = h0;
        }
        default -> {
          a = h2;
          b = h0;
          c = h1;
        }
      }
      data[a] = values[keyIndex[i]] ^ data[b] ^ data[c];
      if (checks != null) {
        checks[a] = fingerprint(hash) ^ checks[b] ^ checks[c];
      }
    }
  }

  // ---------------------------------------------------------------------------------------
  // Serialization.
  //
  // All three formats are little-endian and end with the 64-bit FNV-1a hash of every byte
  // before it:
  //
  //   ConstMap          "CMAP0001" seed:8 segmentLength:4 segmentCount:4 dataLength:4
  //                     data:8*dataLength fnv:8                          (28-byte header)
  //                     fastconstmap writes "CMAP0003": the same with a 4-byte key count
  //                     after dataLength (32-byte header). Both are read.
  //   VerifiedConstMap  "VMAP0001" seed:8 segmentLength:4 segmentCount:4 dataLength:4
  //                     pad:4 data:8*dataLength checks:8*dataLength fnv:8
  //   PairedVerified... "PMAP0001" seed:8 segmentLength:4 segmentCount:4 slotCount:4
  //                     pad:4 (value:8 check:8)*slotCount fnv:8
  //
  // fastconstmap stores its key count in the pad word; every reader ignores it.

  static final long FNV_OFFSET = 0xcbf29ce484222325L;
  static final long FNV_PRIME = 0x100000001b3L;

  static final long MAGIC_CMAP = magic("CMAP0001");
  static final long MAGIC_CMAP_COUNTED = magic("CMAP0003");
  static final long MAGIC_VMAP = magic("VMAP0001");
  static final long MAGIC_PMAP = magic("PMAP0001");
  static final long MAGIC_LEGACY_CMAP = magic("CMAP0002");
  static final long MAGIC_LEGACY_VMAP = magic("VCMP0002");

  static final int CMAP_HEADER = 28;
  static final int VMAP_HEADER = 32;

  /** The kinds of map, for naming a file handed to the wrong reader. */
  enum Kind {
    CONST("ConstMap"),
    VERIFIED("VerifiedConstMap"),
    PAIRED("PairedVerifiedConstMap");

    final String className;

    Kind(String className) {
      this.className = className;
    }
  }

  private static long magic(String s) {
    byte[] b = s.getBytes(StandardCharsets.US_ASCII);
    return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getLong();
  }

  static long fnv(long h, long word) {
    for (int i = 0; i < 8; i++) {
      h ^= word & 0xFF;
      h *= FNV_PRIME;
      word >>>= 8;
    }
    return h;
  }

  static long fnv32(long h, int word) {
    for (int i = 0; i < 4; i++) {
      h ^= word & 0xFF;
      h *= FNV_PRIME;
      word >>>= 8;
    }
    return h;
  }

  /** A little-endian view of {@code out} at its position, after checking the space. */
  static ByteBuffer writer(ByteBuffer out, long size) {
    Objects.requireNonNull(out);
    if (out.isReadOnly()) {
      throw new java.nio.ReadOnlyBufferException();
    }
    if (out.remaining() < size) {
      throw new java.nio.BufferOverflowException();
    }
    return out.duplicate().order(ByteOrder.LITTLE_ENDIAN);
  }

  /**
   * Writes a header and the given arrays (each one after the other) and the checksum, and
   * advances {@code out}'s position.
   */
  static void write(ByteBuffer out, long magic, Params p, int count, boolean pad,
      long[]... arrays) {
    long size = (pad ? VMAP_HEADER : CMAP_HEADER) + 8L;
    for (long[] a : arrays) {
      size += 8L * a.length;
    }
    ByteBuffer w = writer(out, size);
    long h = FNV_OFFSET;
    w.putLong(magic);
    h = fnv(h, magic);
    w.putLong(p.seed());
    h = fnv(h, p.seed());
    w.putInt(p.segmentLength());
    h = fnv32(h, p.segmentLength());
    w.putInt(p.segmentCount());
    h = fnv32(h, p.segmentCount());
    w.putInt(count);
    h = fnv32(h, count);
    if (pad) {
      w.putInt(0);
      h = fnv32(h, 0);
    }
    for (long[] a : arrays) {
      for (long v : a) {
        w.putLong(v);
        h = fnv(h, v);
      }
    }
    w.putLong(h);
    out.position(w.position());
  }

  /**
   * A parsed header: the parameters, the absolute index of the first byte of the serialized
   * map, the header size (so the arrays start at {@code start + headerSize}), and the total
   * size including the checksum.
   */
  record Header(Params params, int start, int headerSize, int totalBytes) {
    int arrayStart() {
      return start + headerSize;
    }
  }

  /**
   * Reads and validates the header of a map of the given kind at the buffer's position, and
   * verifies the trailing checksum over {@code wordsPerPosition} words per array position.
   */
  static Header read(ByteBuffer buffer, Kind kind, int wordsPerPosition) {
    Header h = readHeader(buffer, kind, wordsPerPosition);
    verifyChecksum(buffer, h);
    return h;
  }

  /**
   * Reads and validates the header of a map of the given kind at the buffer's position, in
   * constant time: magic bytes, segment parameters consistent with the array length, and a
   * buffer long enough for the whole map. Does not verify the checksum.
   */
  static Header readHeader(ByteBuffer buffer, Kind kind, int wordsPerPosition) {
    ByteBuffer b = buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN);
    final int start = b.position();
    if (b.remaining() < 8) {
      throw new InvalidFilterException("truncated input: no room for the magic bytes");
    }
    long magic = b.getLong(start);
    boolean counted = false;
    Kind found;
    if (magic == MAGIC_CMAP) {
      found = Kind.CONST;
    } else if (magic == MAGIC_CMAP_COUNTED) {
      found = Kind.CONST;
      counted = true;
    } else if (magic == MAGIC_VMAP) {
      found = Kind.VERIFIED;
    } else if (magic == MAGIC_PMAP) {
      found = Kind.PAIRED;
    } else if (magic == MAGIC_LEGACY_CMAP || magic == MAGIC_LEGACY_VMAP) {
      throw new InvalidFilterException("this file was written by fastconstmap 0.9 or earlier"
          + " with a different key hash (XXH3); rebuild it from its keys with fastconstmap"
          + " 0.10 or later, which writes the shared format");
    } else {
      throw new InvalidFilterException("invalid magic bytes: not a constant map");
    }
    if (found != kind) {
      throw new InvalidFilterException("this is a " + found.className + ", not a "
          + kind.className + "; use " + found.className + ".load or " + found.className
          + ".wrap");
    }
    final int headerSize = (kind == Kind.CONST && !counted) ? CMAP_HEADER : VMAP_HEADER;
    if (b.remaining() < headerSize) {
      throw new InvalidFilterException("truncated input: " + b.remaining()
          + " bytes, the header alone is " + headerSize);
    }
    long seed = b.getLong(start + 8);
    int segmentLength = b.getInt(start + 16);
    int segmentCount = b.getInt(start + 20);
    long count = b.getInt(start + 24) & 0xFFFFFFFFL;
    if (count > MAX_ARRAY_LENGTH) {
      throw new InvalidFilterException("map too large for Java arrays: " + count + " positions");
    }
    long total = headerSize + 8L * wordsPerPosition * count + 8;
    if (b.remaining() < total) {
      throw new InvalidFilterException("truncated input: " + b.remaining()
          + " bytes, expected " + total);
    }
    Params params;
    if (count == 0) {
      params = Params.EMPTY;
    } else {
      if (segmentLength <= 0 || (segmentLength & (segmentLength - 1)) != 0) {
        throw new InvalidFilterException(
            "segment length " + Integer.toUnsignedString(segmentLength) + " is not a power of two");
      }
      if (segmentCount <= 0) {
        throw new InvalidFilterException("invalid segment count "
            + Integer.toUnsignedString(segmentCount));
      }
      if (((long) segmentCount + 2) * segmentLength != count) {
        throw new InvalidFilterException(count + " positions but the segment parameters describe "
            + ((long) segmentCount + 2) * segmentLength);
      }
      params = new Params(seed, segmentLength, segmentCount, (int) count);
    }
    return new Header(params, start, headerSize, (int) total);
  }

  /** Verifies the trailing FNV-1a checksum of a map whose header was read by readHeader. */
  static void verifyChecksum(ByteBuffer buffer, Header header) {
    ByteBuffer b = buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN);
    long h = FNV_OFFSET;
    int end = header.start() + header.totalBytes() - 8;
    int i = header.start();
    for (; i + 8 <= end; i += 8) {
      h = fnv(h, b.getLong(i));
    }
    if (i < end) {
      h = fnv32(h, b.getInt(i));
    }
    long stored = b.getLong(end);
    if (stored != h) {
      throw new InvalidFilterException(String.format(
          "checksum mismatch (stored %016x, computed %016x)", stored, h));
    }
  }

  /**
   * Writes the serialized bytes a view wraps, unchanged, at {@code out}'s position, and
   * advances the position.
   */
  static void copy(ByteBuffer serialized, ByteBuffer out) {
    writer(out, serialized.capacity());
    out.put(serialized.duplicate().clear());
  }

  /**
   * A little-endian slice of {@code bytes} bytes of the buffer from absolute index
   * {@code from}, independent of the buffer's position, limit and byte order.
   */
  static ByteBuffer slice(ByteBuffer buffer, int from, int bytes) {
    return buffer.slice(from, bytes).order(ByteOrder.LITTLE_ENDIAN);
  }

  /** Reads {@code n} little-endian words starting at absolute index {@code from}. */
  static long[] readWords(ByteBuffer buffer, int from, int n) {
    long[] words = new long[n];
    buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN).position(from).asLongBuffer().get(words);
    return words;
  }
}
