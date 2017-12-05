package org.cloudfoundry.credhub.util;

import java.nio.ByteBuffer;
import java.util.UUID;

public class UuidUtil {

  public static Object makeUuid(String databaseName) {
    UUID uuid = UUID.randomUUID();

    if (databaseName.equals("postgresql")) {
      return uuid;
    } else {
      ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
      byteBuffer.putLong(uuid.getMostSignificantBits());
      byteBuffer.putLong(uuid.getLeastSignificantBits());
      return byteBuffer.array();
    }
  }

  public static byte[] uuidToByteArray(UUID uuid) {
    ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
    byteBuffer.putLong(uuid.getMostSignificantBits());
    byteBuffer.putLong(uuid.getLeastSignificantBits());
    return byteBuffer.array();
  }
}
