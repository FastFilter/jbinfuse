package io.github.fastfilter.jbinfuse;

/**
 * Thrown when serialized bytes are not a valid binary fuse filter: wrong magic bytes, an
 * unsupported format version or variant, inconsistent parameters, truncated input or a
 * checksum mismatch.
 */
public final class InvalidFilterException extends IllegalArgumentException {
  private static final long serialVersionUID = 1L;

  /**
   * Creates an exception with the given message.
   *
   * @param message what is wrong with the input
   */
  public InvalidFilterException(String message) {
    super(message);
  }
}
