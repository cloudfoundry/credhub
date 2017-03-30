package io.pivotal.security.service;

import io.pivotal.security.util.ExceptionThrowingFunction;
import org.springframework.http.ResponseEntity;

public interface AuditLogService {
  ResponseEntity<?> performWithAuditing(ExceptionThrowingFunction<AuditRecordBuilder,
      ResponseEntity<?>,
      Exception> action) throws Exception;
}
