package io.vertx.ext.auth.jdbc.impl;

import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the {@link SaltedHashPasswordStrategy} hash computation
 *
 * @author david
 */
public class SaltedHashPasswordStrategyTest {

  private static SaltedHashPasswordStrategy strategy;

  @BeforeClass
  public static void setup() {
    strategy = new SaltedHashPasswordStrategy("SHA-256");
    assertTrue(strategy.isSupported());
  }

  @Test
  public void test_hashComputation_noSalt() {
    final String expected = "taLJYlBhI2bqJy/6xtl0Sq9LRarNlqp8/Lkx7jtVglk=";
    assertThat(strategy.compute("dummy", Optional.empty()), equalTo(expected));
    assertThat(strategy.compute("dummy", Optional.empty()), equalTo(expected));

    // different plaintext password
    assertThat(strategy.compute("dummy1", Optional.empty()), not(equalTo(expected)));
  }

  @Test
  public void test_hashComputation_withSalt() {
    final String expected = "lnSFFNNq0nWKe0sQMiNgPjz6AJcraX1gfaIJUZgpzsk=";
    assertThat(strategy.compute("dummy", Optional.of("abcd")), equalTo(expected));
    assertThat(strategy.compute("dummy", Optional.of("abcd")), equalTo(expected));

    // different plaintext password
    assertThat(strategy.compute("dummy1", Optional.of("abcd")), not(equalTo(expected)));

    // different salt
    assertThat(strategy.compute("dummy", Optional.of("abcde")), not(equalTo(expected)));
  }

}
