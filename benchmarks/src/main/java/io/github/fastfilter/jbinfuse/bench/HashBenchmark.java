package io.github.fastfilter.jbinfuse.bench;

import io.github.fastfilter.jbinfuse.WyHash;
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

/** Average time to hash one byte-array key with wyhash. */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class HashBenchmark {
  static final int KEYS = 1024;

  @Param({"8", "16", "32", "100"})
  int length;

  byte[][] keys;

  @Setup
  public void setup() {
    SplittableRandom r = new SplittableRandom(length);
    keys = new byte[KEYS][length];
    for (byte[] k : keys) {
      r.nextBytes(k);
    }
  }

  @Benchmark
  @OperationsPerInvocation(KEYS)
  public long wyhash() {
    long h = 0;
    for (byte[] k : keys) {
      h += WyHash.hash(k);
    }
    return h;
  }
}
