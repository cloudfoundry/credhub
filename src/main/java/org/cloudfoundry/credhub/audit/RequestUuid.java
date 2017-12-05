package org.cloudfoundry.credhub.audit;

import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

import java.util.UUID;

@Component
@RequestScope
public class RequestUuid {
  private UUID uuid;

  @SuppressWarnings("unused")
  public RequestUuid() {}

  public UUID getUuid() {
    if (uuid == null) {
      uuid = UUID.randomUUID();
    }
    return uuid;
  }
}
