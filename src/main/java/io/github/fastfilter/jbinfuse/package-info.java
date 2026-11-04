/**
 * Binary fuse filters: compact, immutable approximate-membership filters (Graf and Lemire,
 * "Binary Fuse Filters: Fast and Smaller Than Xor Filters", ACM JEA 27, 2022).
 *
 * <p>Build a filter with {@link io.github.fastfilter.jbinfuse.BinaryFuse8#build(long[])} or
 * {@link io.github.fastfilter.jbinfuse.BinaryFuse16#build(long[])} (or their
 * {@code buildFromBytes} variants), serialize it with
 * {@link io.github.fastfilter.jbinfuse.BinaryFuseFilter#serialize(java.nio.ByteBuffer)}, and
 * query the serialized bytes in place with
 * {@link io.github.fastfilter.jbinfuse.BinaryFuseFilter#wrap(java.nio.ByteBuffer)}.
 *
 * <p>The same construction also gives compact immutable maps from keys to 64-bit values:
 * {@link io.github.fastfilter.jbinfuse.ConstMap} (about 9 bytes per key, arbitrary answers for
 * missing keys), and {@link io.github.fastfilter.jbinfuse.VerifiedConstMap} and
 * {@link io.github.fastfilter.jbinfuse.PairedVerifiedConstMap} (about 18 bytes per key, missing
 * keys detected). Their files are interchangeable with those of the Go, Rust and C/Python
 * implementations (constmap, rsconstmap, fastconstmap).
 */
package io.github.fastfilter.jbinfuse;
