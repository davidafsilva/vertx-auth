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
public class SaltedHashPasswordStrategy extends AbstractPasswordStrategy {

  // the hash algorithm
  private final String algorithm;

  /**
   * Creates a new hashed strategy with the given hashing algorithm
   *
   * @param algorithm the hash algorithm
   */
  public SaltedHashPasswordStrategy(final String algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Checks whether or not the configured algorithm is available from the available security
   * providers
   *
   * @return {@code true} if the algorithm is available, {@code false} otherwise.
   */
  public boolean isSupported() {
    boolean supported = true;
    try {
      MessageDigest.getInstance(algorithm);
    } catch (final NoSuchAlgorithmException e) {
      // no algorithm available
      supported = false;
    }
    return supported;
  }

  @Override
  public String compute(final String password, final Optional<String> salt) {
    try {
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
