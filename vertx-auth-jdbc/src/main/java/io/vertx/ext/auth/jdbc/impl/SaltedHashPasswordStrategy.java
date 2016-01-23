package io.vertx.ext.auth.jdbc.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import io.vertx.core.VertxException;
import io.vertx.ext.auth.jdbc.PasswordEncoder;

/**
 * <p>
 * This implementation of the password strategy contract transforms the password into an hash
 * by applying the configured hash algorithm to the password input (plaintext).
 * It optionally prepends a salt to the input prior to hashing the password, if one is specified.
 * </p>
 *
 * <p>
 * The output of this implementation will use a Base64 encoder if one is not specified via
 * {@link #encoder(PasswordEncoder)}.
 * </p>
 *
 * @author david
 */
public class SaltedHashPasswordStrategy extends AbstractHashStrategy {

  /**
   * Creates a new hashed strategy with the given hashing algorithm
   *
   * @param algorithm the hash algorithm
   */
  public SaltedHashPasswordStrategy(final String algorithm) {
    super(algorithm);
  }

  @Override
  boolean isAlgorithmSupported() throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algorithm) != null;
  }

  @Override
  public String compute(final String password, final Optional<String> salt) {
    try {
      // get the digest algorithm implementation instance
      final MessageDigest md = MessageDigest.getInstance(algorithm);
      md.reset();

      // update the digest with the salt
      salt.map(s -> s.getBytes(StandardCharsets.UTF_8)).ifPresent(md::update);

      // hash the password
      final byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));

      // return the encoded hash
      return encoder.encode(hash);
    } catch (final NoSuchAlgorithmException e) {
      throw new VertxException(e);
    }
  }
}
