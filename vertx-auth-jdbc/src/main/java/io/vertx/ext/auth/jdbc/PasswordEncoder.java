package io.vertx.ext.auth.jdbc;

import io.vertx.ext.auth.jdbc.encoder.Base64Encoder;
import io.vertx.ext.auth.jdbc.encoder.HexEncoder;

/**
 * Defines how {@link PasswordStrategy strategies} encode their passwords prior to returning
 * from its implementation.
 *
 * @author david
 */
public interface PasswordEncoder {

  /**
   * Returns a new hex encoder which will transform byte data into his hexadecimal textual
   * representation.
   * Note that the defined hexadecimal alphabet for the transformation is in upper case (0-9A-F).
   *
   * @return the hexadecimal encoder
   */
  static PasswordEncoder hex() {
    return new HexEncoder();
  }

  /**
   * Returns a new base64 encoder which will transform byte data into a base64 textual
   * representation using the "Base64 Alphabet" as specified in Table 1 of RFC 4648 and RFC 2045.
   *
   * @return the base64 encoder
   */
  static PasswordEncoder base64() {
    return new Base64Encoder();
  }

  /**
   * Converts the given byte array to a textual representation.
   *
   * @param data the byte array data
   * @return the textual representation of the data
   */
  String encode(final byte[] data);
}
