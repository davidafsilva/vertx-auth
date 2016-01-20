package io.vertx.ext.auth.jdbc.encoder;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for the {@link HexEncoder}.
 *
 * @author david
 */
public class HexEncoderTest {

  @Test
  public void test_encode() {
    final HexEncoder encoder = new HexEncoder();
    assertThat(encoder.encode("vertx".getBytes(StandardCharsets.UTF_8)), equalTo("7665727478"));
    assertThat(encoder.encode("oink".getBytes(StandardCharsets.UTF_8)), equalTo("6F696E6B"));
    assertThat(encoder.encode("123!#$%&".getBytes(StandardCharsets.UTF_8)), equalTo("3132332123242526"));
  }
}
