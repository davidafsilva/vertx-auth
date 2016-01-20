package io.vertx.ext.auth.jdbc;

import org.junit.Test;

import java.security.Security;
import java.util.Optional;

import static org.junit.Assert.assertFalse;

/**
 * Unit tests for the {@link PasswordStrategy} static factory methods.
 *
 * @author david
 */
public class PasswordStrategyTest {

  @Test
  public void test_supportedAlgorithms() {
    Security.getAlgorithms("MESSAGEDIGEST").stream()
        .map(PasswordStrategy::create)
        .allMatch(Optional::isPresent);
  }

  @Test
  public void test_supportedAlgorithmsWithEncoder() {
    Security.getAlgorithms("MESSAGEDIGEST").stream()
        .map(alg -> PasswordStrategy.create(alg, PasswordEncoder.hex()))
        .allMatch(Optional::isPresent);
  }

  @Test
  public void test_unsupportedAlgorithm() {
    assertFalse(PasswordStrategy.create("BLOWFISH").isPresent());
    assertFalse(PasswordStrategy.create("AES_256/CBC/NOPADDING").isPresent());
    assertFalse(PasswordStrategy.create("DES").isPresent());
    assertFalse(PasswordStrategy.create("yolo-512").isPresent());
  }
}
