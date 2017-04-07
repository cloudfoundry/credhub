package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class NotRegeneratable implements Regeneratable {

  private ErrorResponseService errorResponseService;

  public NotRegeneratable(ErrorResponseService errorResponseService) {

    this.errorResponseService = errorResponseService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    return new ResponseEntity<>(errorResponseService.createErrorResponse("error.invalid_type_with_regenerate_prompt"), HttpStatus.BAD_REQUEST);
  }
}
