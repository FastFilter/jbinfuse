package io.github.fastfilter.jbinfuse.bench;

import io.github.fastfilter.jbinfuse.BinaryFuse16;
import io.github.fastfilter.jbinfuse.BinaryFuse8;
import io.github.fastfilter.jbinfuse.BinaryFuseFilter;
import java.util.SplittableRandom;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/** Construction time for random 64-bit keys. */
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3)
@Measurement(iterations = 10)
@Fork(1)
@State(Scope.Benchmark)
public class BuildBenchmark {
  @Param({"1000000", "10000000"})
  int size;

  @Param({"8", "16"})
  int bits;

  long[] keys;

  @Setup
  public void setup() {
    SplittableRandom r = new SplittableRandom(size);
    keys = new long[size];
    for (int i = 0; i < size; i++) {
      keys[i] = r.nextLong();
    }
  }

  @Benchmark
  public BinaryFuseFilter build() {
    return bits == 8 ? BinaryFuse8.build(keys) : BinaryFuse16.build(keys);
  }
}
