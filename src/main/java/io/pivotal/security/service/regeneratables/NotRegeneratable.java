package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.AuditRecordBuilder;
import org.springframework.http.ResponseEntity;

public class NotRegeneratable implements Regeneratable {

  public NotRegeneratable() {
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    throw new ParameterizedValidationException("error.invalid_type_with_regenerate_prompt");
  }
}
