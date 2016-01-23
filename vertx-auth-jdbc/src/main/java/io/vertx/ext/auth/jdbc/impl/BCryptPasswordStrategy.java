package io.vertx.ext.auth.jdbc.impl;

import org.mindrot.jbcrypt.BCrypt;

import java.util.Optional;

import io.vertx.core.VertxException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.jdbc.PasswordEncoder;
import io.vertx.ext.auth.jdbc.PasswordStrategy;

/**
 * <p>
 * This implementation of the password strategy contract transforms a specified password and salt
 * into an BCrypt hash, as such, it requires a salt to the supplied along with the password.
 *
 * BCrypt is indeed safer than regular hashing algorithms for password verification, but due to its
 * design, they're far more expensive to compute (thus safer to BF attacks) which might not be
 * ideal to performance critical applications.
 * </p>
 *
 * <p>
 * The output of this implementation does not supported a custom encoder.
 * </p>
 *
 * @author david
 */
public class BCryptPasswordStrategy implements PasswordStrategy {

  // the class logger
  private static final Logger LOGGER = LoggerFactory.getLogger(BCryptPasswordStrategy.class);

  @Override
  public PasswordStrategy encoder(final PasswordEncoder encoder) {
    LOGGER.warn("defining an encoder will have no affect when using a BCrypt strategy");
    return this;
  }

  @Override
  public String compute(final String password, final Optional<String> salt) {
    return BCrypt.hashpw(password,
        salt.orElseThrow(() -> new VertxException("salt is required for BCrypt")));
  }

  @Override
  public String getPasswordFromQueryResult(final JsonArray row) {
    return row.getString(0);
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
