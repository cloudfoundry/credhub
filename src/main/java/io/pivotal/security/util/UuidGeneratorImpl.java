package io.pivotal.security.util;

import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class UuidGeneratorImpl implements UuidGenerator {
  @Override
  public String makeUuid() {
    return UUID.randomUUID().toString();
  }
}
