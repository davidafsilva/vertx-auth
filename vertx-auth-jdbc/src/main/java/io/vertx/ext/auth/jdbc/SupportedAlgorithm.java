package io.vertx.ext.auth.jdbc;

import java.security.Security;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.BiFunction;

import io.vertx.ext.auth.jdbc.impl.BCryptPasswordStrategy;
import io.vertx.ext.auth.jdbc.impl.HmacPasswordStrategy;
import io.vertx.ext.auth.jdbc.impl.SaltedHashPasswordStrategy;

/**
 * This facility enumerates and provides a mapping for the supported algorithms and their concrete
 * password strategies that are provided as part of this vert.x auth module.
 *
 * @author david
 */
enum SupportedAlgorithm {
  HMAC((a, e) -> new HmacPasswordStrategy(a).encoder(e)),
  MESSAGEDIGEST((a, e) -> new SaltedHashPasswordStrategy(a).encoder(e)),
  BCRYPT((a, e) -> new BCryptPasswordStrategy());

  // the supported algorithms
  private static final Map<String, SupportedAlgorithm> ALGORITHMS;

  // create the algorithm mapping by looking up the available security providers and
  // their supported algorithms for each type
  static {
    ALGORITHMS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    Arrays.stream(SupportedAlgorithm.values())
        .forEach(type -> Security.getAlgorithms(type.name()).stream()
            .forEach(algorithm -> ALGORITHMS.put(algorithm, type)));
    ALGORITHMS.put(SupportedAlgorithm.BCRYPT.name(), SupportedAlgorithm.BCRYPT);
  }

  // the factory function
  private final BiFunction<String, PasswordEncoder, PasswordStrategy> factory;

  // enum constructor - receives the underlying factory function
  SupportedAlgorithm(final BiFunction<String, PasswordEncoder, PasswordStrategy> factory) {
    this.factory = factory;
  }

  /**
   * Returns the factory function for the instantiation of this type of algorithm
   *
   * @return the factory function
   */
  private BiFunction<String, PasswordEncoder, PasswordStrategy> getFactory() {
    return factory;
  }

  /**
   * Returns a password strategy with the specified algorithm based on the available and supported
   * algorithms.
   *
   * @param algorithm the desired algorithm
   * @param encoder   the output encoder to the passed onto the strategy
   * @return a new instance of the password strategy if the algorithm is supported
   */
  static Optional<PasswordStrategy> create(final String algorithm, final PasswordEncoder encoder) {
    return Optional.ofNullable(ALGORITHMS.get(algorithm))
        .map(SupportedAlgorithm::getFactory)
        .map(f -> f.apply(algorithm, encoder));
  }
}
