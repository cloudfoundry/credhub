package io.pivotal.security.util;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.UUID;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

public class UuidUtilTest {
  @Test
  public void roundtripUuid() throws Exception {
    UUID originalUuid = UUID.randomUUID();

    byte[] translatedUuid = UuidUtil.uuidToByteArray(originalUuid);

    ByteBuffer buffer = ByteBuffer.wrap(translatedUuid);
    assertThat(new UUID(buffer.getLong(), buffer.getLong()), equalTo(originalUuid));
  }
}