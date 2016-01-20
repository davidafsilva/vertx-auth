package io.vertx.ext.auth.jdbc.impl;

import java.util.Objects;
import java.util.Optional;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.PasswordEncoder;
import io.vertx.ext.auth.jdbc.PasswordStrategy;

/**
 * This abstract implementation provides a common code-base for the provided password strategies
 * implementation.
 *
 * @author david
 */
abstract class AbstractPasswordStrategy implements PasswordStrategy {

  // the password encoder - by default, a Base64 encoder is used
  protected PasswordEncoder encoder = PasswordEncoder.base64();

  @Override
  public AbstractPasswordStrategy encoder(final PasswordEncoder encoder) {
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
