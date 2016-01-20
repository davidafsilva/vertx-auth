package io.vertx.ext.auth.jdbc.encoder;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for the {@link Base64Encoder}.
 *
 * @author david
 */
public class Base64EncoderTest {

  @Test
  public void test_encode() {
    final Base64Encoder encoder = new Base64Encoder();
    assertThat(encoder.encode("vertx".getBytes(StandardCharsets.UTF_8)), equalTo("dmVydHg="));
    assertThat(encoder.encode("oink".getBytes(StandardCharsets.UTF_8)), equalTo("b2luaw=="));
    assertThat(encoder.encode("123!#$%&".getBytes(StandardCharsets.UTF_8)), equalTo("MTIzISMkJSY="));

  }
}
