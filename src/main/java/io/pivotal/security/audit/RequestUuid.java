package io.pivotal.security.audit;

import java.util.UUID;

public class RequestUuid {
  private final UUID uuid;

  @SuppressWarnings("unused")
  public RequestUuid() { uuid = null; }

  public RequestUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public UUID getUuid() {
    return uuid;
  }
}
