package io.pivotal.security.service;

import java.util.function.Supplier;
import org.springframework.http.ResponseEntity;

public interface AuditLogService {

  ResponseEntity<?> performWithAuditing(AuditRecordBuilder auditRecordBuilder,
      Supplier<ResponseEntity<?>> action) throws Exception;
}
