package io.vertx.ext.auth.jdbc.impl;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Optional;

import io.vertx.core.VertxException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the {@link HmacPasswordStrategy} hash computation
 *
 * @author david
 */
public class HmacPasswordStrategyTest {

  private static HmacPasswordStrategy strategy;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @BeforeClass
  public static void setup() {
    strategy = new HmacPasswordStrategy("HMACSHA256");
    assertTrue(strategy.isSupported());
  }

  @Test
  public void test_hashComputation_noSalt() {
    thrown.expect(VertxException.class);
    thrown.expectMessage("salt is required for HMAC");
    strategy.compute("dummy", Optional.empty());
  }

  @Test
  public void test_hashComputation() {
    final String expected = "8nVaS1OlKec8l5dnW0rU6Dk6B8H9hUiRhoue4Z1DuCU=";
    assertThat(strategy.compute("dummy", Optional.of("abcd")), equalTo(expected));
    assertThat(strategy.compute("dummy", Optional.of("abcd")), equalTo(expected));

    // different plaintext password
    assertThat(strategy.compute("dummy1", Optional.of("abcd")), not(equalTo(expected)));

    // different salt
    assertThat(strategy.compute("dummy", Optional.of("abcde")), not(equalTo(expected)));
  }
}
