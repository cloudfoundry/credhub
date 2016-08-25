package io.pivotal.security.fake;

import io.pivotal.security.util.UuidGenerator;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Primary
@Profile("FakeUuidGenerator")
public class FakeUuidGenerator implements UuidGenerator {
  @Override
  public String makeUuid() {
    return "47c37cff-6d48-49ff-a294-3eca9b716e10";
  }
}
