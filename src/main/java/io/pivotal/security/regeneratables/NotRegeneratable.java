package io.pivotal.security.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.service.AuditRecordBuilder;
import org.springframework.http.ResponseEntity;

public class NotRegeneratable implements Regeneratable {

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    // This should be replaced with Exception "error.invalid_type_with_regenerate_prompt"
    // Currently calling code expects null to handle the type not being handled.
    return null;
  }
}
