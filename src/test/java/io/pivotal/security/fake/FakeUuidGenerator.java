package io.pivotal.security.fake;

import io.pivotal.security.util.UuidGenerator;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
@Primary
@Profile("FakeUuidGenerator")
public class FakeUuidGenerator implements UuidGenerator {

  private final List<UUID> uuids = new ArrayList<>();

  @Override
  public String makeUuid() {
    UUID uuid = nextUuid();
    uuids.add(0, uuid);
    return uuid.toString();
  }

  private UUID nextUuid() {
    UUID uuid;
    if (uuids.size() == 0) {
      uuid = new UUID(0, 0);
    } else {
      uuid = uuids.get(0);
    }
    UUID lastUuid = UUID.fromString(uuid.toString());
    ByteBuffer byteBuffer = ByteBuffer.allocate(16);
    byteBuffer.putLong(lastUuid.getMostSignificantBits());
    byteBuffer.putLong(lastUuid.getLeastSignificantBits());
    BigInteger bigInteger = new BigInteger(byteBuffer.array());
    bigInteger = bigInteger.add(BigInteger.ONE);
    byte[] bytes = new byte[16];
    byte[] bigIntBytes = bigInteger.toByteArray();
    System.arraycopy(bigIntBytes, 0, bytes, 16 - bigIntBytes.length, bigIntBytes.length);
    byteBuffer = ByteBuffer.wrap(bytes);
    uuid = new UUID(byteBuffer.getLong(0), byteBuffer.getLong(8));
    return uuid;
  }

  public String getLastUuid() {
    if (uuids.size() == 0) {
      throw new IllegalStateException("what is the last of none?");
    }
    return uuids.get(0).toString();
  }

  public String peekNextUuid() {
    return nextUuid().toString();
  }

  public static void main(String... args) {
    FakeUuidGenerator fakeUuidGenerator = new FakeUuidGenerator();
    System.out.println(fakeUuidGenerator.makeUuid());
    System.out.println(fakeUuidGenerator.makeUuid());
    System.out.println(fakeUuidGenerator.makeUuid());
    System.out.println(fakeUuidGenerator.makeUuid());
  }
}
