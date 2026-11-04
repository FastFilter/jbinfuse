package io.github.fastfilter.jbinfuse.bench;

import io.github.fastfilter.jbinfuse.BinaryFuse16;
import io.github.fastfilter.jbinfuse.BinaryFuse8;
import io.github.fastfilter.jbinfuse.BinaryFuseFilter;
import java.nio.ByteBuffer;
import java.util.SplittableRandom;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/** Average time of one {@code contains(long)} query, half hits and half misses. */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class QueryBenchmark {
  static final int QUERIES = 1 << 16;

  @Param({"1000000", "10000000"})
  int size;

  @Param({"heap8", "heap16", "direct8", "direct16"})
  String kind;

  BinaryFuseFilter filter;
  long[] queries;

  @Setup
  public void setup() {
    SplittableRandom r = new SplittableRandom(size);
    long[] keys = new long[size];
    for (int i = 0; i < size; i++) {
      keys[i] = r.nextLong();
    }
    BinaryFuseFilter f = kind.endsWith("16") ? BinaryFuse16.build(keys) : BinaryFuse8.build(keys);
    if (kind.startsWith("direct")) {
      ByteBuffer buf = ByteBuffer.allocateDirect(f.serializedSize());
      f.serialize(buf);
      buf.flip();
      f = BinaryFuseFilter.wrap(buf);
    }
    filter = f;
    queries = new long[QUERIES];
    for (int i = 0; i < QUERIES; i++) {
      queries[i] = (i & 1) == 0 ? keys[r.nextInt(size)] : r.nextLong();
    }
  }

  @Benchmark
  @OperationsPerInvocation(QUERIES)
  public int contains() {
    int count = 0;
    BinaryFuseFilter f = filter;
    for (long q : queries) {
      count += f.contains(q) ? 1 : 0;
    }
    return count;
  }
}
