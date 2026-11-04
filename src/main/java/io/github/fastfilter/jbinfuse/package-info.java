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
 */
package io.github.fastfilter.jbinfuse;
