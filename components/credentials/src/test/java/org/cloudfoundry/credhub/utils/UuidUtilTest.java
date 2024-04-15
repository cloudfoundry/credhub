package org.cloudfoundry.credhub.utils;

import java.nio.ByteBuffer;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class UuidUtilTest {

  @Test
  public void roundtripUuid() throws Exception {
    final UUID originalUuid = UUID.randomUUID();

    final byte[] translatedUuid = UuidUtil.uuidToByteArray(originalUuid);

    final ByteBuffer buffer = ByteBuffer.wrap(translatedUuid);
    assertThat(new UUID(buffer.getLong(), buffer.getLong()), equalTo(originalUuid));
  }
}
