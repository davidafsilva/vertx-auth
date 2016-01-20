package io.vertx.ext.auth.jdbc.encoder;

import java.util.Base64;

import io.vertx.ext.auth.jdbc.PasswordEncoder;

/**
 * This encoder will transform byte data into a base64 textual representation using the
 * "Base64 Alphabet" as specified in Table 1 of RFC 4648 and RFC 2045.
 *
 * @author david
 */
public class Base64Encoder implements PasswordEncoder {

  @Override
  public String encode(final byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }
}
