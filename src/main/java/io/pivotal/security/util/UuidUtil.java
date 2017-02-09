package io.pivotal.security.util;

import java.nio.ByteBuffer;
import java.util.UUID;

public class UuidUtil {
  public static byte[] uuidToByteArray(UUID uuid) {
    ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
    byteBuffer.putLong(uuid.getMostSignificantBits());
    byteBuffer.putLong(uuid.getLeastSignificantBits());
    return byteBuffer.array();
  }
}
