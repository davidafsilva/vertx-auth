package io.vertx.ext.auth.jdbc.encoder;

import io.vertx.ext.auth.jdbc.PasswordEncoder;

/**
 * This encoder will transform byte data into his hexadecimal textual representation.
 * Note that the defined hexadecimal alphabet for the transformation is in upper case (0-9A-F).
 *
 * @author david
 */
public class HexEncoder implements PasswordEncoder {

  // the hexadecimal alphabet
  private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

  @Override
  public String encode(final byte[] data) {
    final char[] chars = new char[data.length * 2];
    for (int i = 0; i < data.length; i++) {
      int x = 0xFF & data[i];
      chars[i * 2] = HEX_CHARS[x >>> 4];
      chars[1 + i * 2] = HEX_CHARS[0x0F & x];
    }

    return String.valueOf(chars);
  }
}
