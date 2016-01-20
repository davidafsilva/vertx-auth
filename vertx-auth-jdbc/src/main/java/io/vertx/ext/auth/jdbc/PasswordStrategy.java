/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.jdbc;

import java.util.Objects;
import java.util.Optional;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.impl.SaltedHashPasswordStrategy;

/**
 * Defines the base contract for the password computation strategies that are implemented in
 * order to properly adapt to different mechanisms and systems that authenticate/generate
 * password in different ways.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 * @author david
 */
public interface PasswordStrategy {

  /**
   * Creates a default hash strategy with the specified algorithm based on the available security
   * providers, following the Java Cryptography Architecture (JCA). The preferred provider will
   * be used when multiple provider are available for the same algorithm.
   * By default, a Base64 {@link PasswordEncoder encoder} will be used, which is more compact then
   * hexadecimal.
   *
   * @param algorithm the algorithm
   * @return a new instance of the hash strategy if the algorithm is supported, none if it's not.
   * @see #create(String, PasswordEncoder)
   */
  static Optional<PasswordStrategy> create(final String algorithm) {
    return create(algorithm, PasswordEncoder.base64());
  }

  /**
   * Creates a default hash strategy with the specified algorithm based on the available security
   * providers, following the Java Cryptography Architecture (JCA). The preferred provider will
   * be used when multiple provider are available for the same algorithm.
   * The output of the strategy compute function will be encoded with the specified encoder.
   *
   * @param algorithm the algorithm
   * @param encoder   the output encoder
   * @return a new instance of the hash strategy if the algorithm is supported, none if it's not.
   */
  static Optional<PasswordStrategy> create(final String algorithm, final PasswordEncoder encoder) {
    Objects.requireNonNull(algorithm, "algorithm");
    final SaltedHashPasswordStrategy strategy = new SaltedHashPasswordStrategy(algorithm);
    return strategy.isSupported() ? Optional.of(strategy.encoder(encoder)) : Optional.empty();
  }

  /**
   * Defines the password encoder to be used when generating the output of computation.
   *
   * @param encoder the encoder to be used
   * @return the password strategy itself for a fluent API
   * @see #compute(String, Optional)
   */
  PasswordStrategy encoder(final PasswordEncoder encoder);

  /**
   * Applies the defined hashing strategy to the given password in its plaintext form and a
   * salt (nonce) value and computes a key (hashed password)
   *
   * @param password the password to derive a key from
   * @param salt     the salt to be used in the computation
   * @return the hashed password
   */
  String compute(final String password, final Optional<String> salt);

  /**
   * Retrieves the hashed password from the row data of the authentication query
   *
   * @param row the row data
   * @return the hashed password
   */
  String getPasswordFromQueryResult(final JsonArray row);

  /**
   * Retrieve the salt from the row data of the authentication query, if salts are supported
   * by the implementation.
   *
   * @param row the row data
   * @return the salt, if any
   */
  Optional<String> getSaltFromQueryResult(final JsonArray row);
}
