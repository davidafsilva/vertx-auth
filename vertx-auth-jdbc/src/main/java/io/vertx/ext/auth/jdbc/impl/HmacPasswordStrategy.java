package io.vertx.ext.auth.jdbc.impl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.vertx.core.VertxException;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.PasswordEncoder;

/**
 * <p>
 * This implementation of the password strategy contract transforms the password into an hash
 * by applying the configured hash-based message authentication code (HMAC) algorithm to the
 * password
 * input (plaintext).
 * It requires a salt to the supplied along with the password in order to properly setup the
 * key for the HMAC.
 * </p>
 *
 * <p>
 * The output of this implementation will use a Base64 encoder if one is not specified via
 * {@link #encoder(PasswordEncoder)}.
 * </p>
 *
 * @author david
 */
public class HmacPasswordStrategy extends AbstractHashStrategy {

  /**
   * Creates a new HMAC hash strategy with the given algorithm
   *
   * @param algorithm the HMAC algorithm
   */
  public HmacPasswordStrategy(final String algorithm) {
    super(algorithm);
  }

  @Override
  boolean isAlgorithmSupported() throws NoSuchAlgorithmException {
    Mac.getInstance(algorithm);
    return true;
  }

  @Override
  public String compute(final String password, final Optional<String> salt) {
    try {
      // get the MAC algorithm implementation instance
      final Mac mac = Mac.getInstance(algorithm);
      mac.reset();

      // derive the key from the salt and initialize the MAC instance with it
      final SecretKeySpec key = salt.map(s -> s.getBytes(StandardCharsets.UTF_8))
          .map(s -> new SecretKeySpec(s, algorithm))
          .orElseThrow(() -> new VertxException("salt is required for HMAC"));
      mac.init(key);

      // compute the MAC with the password
      final byte[] digest = mac.doFinal(password.getBytes(StandardCharsets.UTF_8));

      // return the encoded MAC
      return encoder.encode(digest);
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      throw new VertxException(e);
    }
  }

  /**
   * Retrieve the salt from the row data of the authentication query, if salt is not available,
   * a {@link NullPointerException} will be thrown.
   *
   * @param row the row data
   * @return the salt, if any
   * @throws NullPointerException if the salt is not available
   */
  @Override
  public Optional<String> getSaltFromQueryResult(final JsonArray row) {
    return Optional.of(row.getString(1));
  }
}
