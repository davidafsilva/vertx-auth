package io.vertx.ext.auth.jdbc.impl;

import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.PasswordEncoder;
import io.vertx.ext.auth.jdbc.PasswordStrategy;

/**
 * This abstract implementation provides a common code-base for the provided hash based
 * password strategies implementations.
 * It provides a default Base64 encoder to encode the output of the hash functions.
 *
 * @author david
 */
abstract class AbstractHashStrategy implements PasswordStrategy {

  // the hash algorithm
  protected final String algorithm;

  // the password encoder - by default, a Base64 encoder is used
  protected PasswordEncoder encoder = PasswordEncoder.base64();

  /**
   * Creates a new hashed based strategy with the given hashing algorithm
   *
   * @param algorithm the hash algorithm
   */
  AbstractHashStrategy(final String algorithm) {
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
      isAlgorithmSupported();
    } catch (final NoSuchAlgorithmException e) {
      // no algorithm available
      supported = false;
    }
    return supported;
  }

  abstract boolean isAlgorithmSupported() throws NoSuchAlgorithmException;

  @Override
  public AbstractHashStrategy encoder(final PasswordEncoder encoder) {
    this.encoder = Objects.requireNonNull(encoder, "encoder");
    return this;
  }

  @Override
  public String getPasswordFromQueryResult(JsonArray row) {
    return row.getString(0);
  }

  @Override
  public Optional<String> getSaltFromQueryResult(JsonArray row) {
    return Optional.ofNullable(row.getString(1));
  }

}
