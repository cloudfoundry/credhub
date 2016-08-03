package io.pivotal.security.service;

import org.springframework.http.ResponseEntity;

import java.util.function.Supplier;

public interface AuditLogService {
  ResponseEntity<?> performWithAuditing(String operation, String hostName, String path, Supplier<ResponseEntity<?>> action);
}
