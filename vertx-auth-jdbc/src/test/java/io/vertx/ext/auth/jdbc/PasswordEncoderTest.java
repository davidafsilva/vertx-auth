package io.vertx.ext.auth.jdbc;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for the {@link PasswordEncoder} static factory methods.
 *
 * @author david
 */
public class PasswordEncoderTest {

  @Test
  public void test_hex() {
    final PasswordEncoder encoder = PasswordEncoder.hex();
    assertNotNull(encoder);
    assertThat(encoder.encode("vertx".getBytes(StandardCharsets.UTF_8)), equalTo("7665727478"));
  }

  @Test
  public void test_base64() {
    final PasswordEncoder encoder = PasswordEncoder.base64();
    assertNotNull(encoder);
    assertThat(encoder.encode("vertx".getBytes(StandardCharsets.UTF_8)), equalTo("dmVydHg="));
  }
}
