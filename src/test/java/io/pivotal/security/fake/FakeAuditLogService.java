package io.pivotal.security.fake;

import io.pivotal.security.service.AuditLogService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Primary;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@SuppressWarnings("unused")
@Component
@Primary
@ConditionalOnExpression("#{!environment.getProperty('spring.profiles.active').contains('AuditLogConfigurationTest')}")
public class FakeAuditLogService implements AuditLogService {

  @Override
  public ResponseEntity<?> performWithAuditing(String operation, String hostName, String path, Supplier<ResponseEntity<?>> action) {
    return action.get();
  }
}
