package org.cloudfoundry.credhub.utils;

import java.nio.ByteBuffer;
import java.util.UUID;

final public class UuidUtil {

  private UuidUtil() {
    super();
  }

  public static Object makeUuid(final String databaseName) {
    final UUID uuid = UUID.randomUUID();

    if ("postgresql".equals(databaseName)) {
      return uuid;
    } else {
      final ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
      byteBuffer.putLong(uuid.getMostSignificantBits());
      byteBuffer.putLong(uuid.getLeastSignificantBits());
      return byteBuffer.array();
    }
  }

  public static byte[] uuidToByteArray(final UUID uuid) {
    final ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
    byteBuffer.putLong(uuid.getMostSignificantBits());
    byteBuffer.putLong(uuid.getLeastSignificantBits());
    return byteBuffer.array();
  }
}
