package org.cloudfoundry.credhub.util;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import java.nio.ByteBuffer;
import java.util.UUID;
import org.junit.Test;

public class UuidUtilTest {

  @Test
  public void roundtripUuid() throws Exception {
    UUID originalUuid = UUID.randomUUID();

    byte[] translatedUuid = UuidUtil.uuidToByteArray(originalUuid);

    ByteBuffer buffer = ByteBuffer.wrap(translatedUuid);
    assertThat(new UUID(buffer.getLong(), buffer.getLong()), equalTo(originalUuid));
  }
}
