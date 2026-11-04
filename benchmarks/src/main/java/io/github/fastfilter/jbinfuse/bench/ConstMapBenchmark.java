package io.github.fastfilter.jbinfuse.bench;

import io.github.fastfilter.jbinfuse.ConstMap;
import io.github.fastfilter.jbinfuse.PairedVerifiedConstMap;
import io.github.fastfilter.jbinfuse.VerifiedConstMap;
import java.util.ArrayList;
import java.util.List;
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

/**
 * Average time of one lookup of a present string key, in random order, one at a time with
 * {@code get(String)} or in batches with {@code getMany}. The query strings are allocated in
 * query order, so that reading them does not add scattered loads that belong to the caller
 * rather than to the map.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class ConstMapBenchmark {
  static final int QUERIES = 1 << 16;

  @Param({"1000000", "10000000"})
  int size;

  @Param({"const", "verified", "paired"})
  String kind;

  ConstMap cm;
  VerifiedConstMap vm;
  PairedVerifiedConstMap pm;
  List<String> queries;
  long[] out;

  @Setup
  public void setup() {
    List<String> keys = new ArrayList<>(size);
    long[] values = new long[size];
    for (int i = 0; i < size; i++) {
      keys.add("key-" + i + "-" + Integer.toHexString(i * 0x9E3779B9));
      values[i] = i;
    }
    switch (kind) {
      case "const" -> cm = ConstMap.build(keys, values);
      case "verified" -> vm = VerifiedConstMap.build(keys, values);
      default -> pm = PairedVerifiedConstMap.build(keys, values);
    }
    SplittableRandom r = new SplittableRandom(size);
    queries = new ArrayList<>(QUERIES);
    for (int i = 0; i < QUERIES; i++) {
      // A copy of the chars, not new String(key), which would share the key's array.
      queries.add(new String(keys.get(r.nextInt(size)).toCharArray()));
    }
    out = new long[QUERIES];
  }

  @Benchmark
  @OperationsPerInvocation(QUERIES)
  public long get() {
    long sum = 0;
    switch (kind) {
      case "const" -> {
        for (String q : queries) {
          sum += cm.get(q);
        }
      }
      case "verified" -> {
        for (String q : queries) {
          sum += vm.get(q);
        }
      }
      default -> {
        for (String q : queries) {
          sum += pm.get(q);
        }
      }
    }
    return sum;
  }

  @Benchmark
  @OperationsPerInvocation(QUERIES)
  public long[] getMany() {
    switch (kind) {
      case "const" -> cm.getMany(queries, out);
      case "verified" -> vm.getMany(queries, out);
      default -> pm.getMany(queries, out);
    }
    return out;
  }
}
