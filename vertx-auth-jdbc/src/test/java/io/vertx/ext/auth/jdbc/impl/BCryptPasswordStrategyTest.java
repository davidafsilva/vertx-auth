package io.vertx.ext.auth.jdbc.impl;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Optional;

import io.vertx.core.VertxException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for the {@link BCryptPasswordStrategy} hash computation
 *
 * @author david
 */
public class BCryptPasswordStrategyTest {

  private static BCryptPasswordStrategy strategy;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @BeforeClass
  public static void setup() {
    strategy = new BCryptPasswordStrategy();
  }

  @Test
  public void test_hashComputation_noSalt() {
    thrown.expect(VertxException.class);
    thrown.expectMessage("salt is required for BCrypt");
    strategy.compute("dummy", Optional.empty());
  }

  @Test
  public void test_hashComputation() {
    final String expected = "$2a$10$mqmlykQYwhENka0U4t84J.3Yr.CaQE..mKbeQp5Rjo9nUZF7irQK2";
    final Optional<String> salt = Optional.of("$2a$10$mqmlykQYwhENka0U4t84J.");
    assertThat(strategy.compute("dummy", salt), equalTo(expected));
    assertThat(strategy.compute("dummy", salt), equalTo(expected));

    // different plaintext password
    assertThat(strategy.compute("dummy1", salt), not(equalTo(expected)));

    // different salt
    assertThat(strategy.compute("dummy", Optional.of(BCrypt.gensalt())), not(equalTo(expected)));
  }

}
