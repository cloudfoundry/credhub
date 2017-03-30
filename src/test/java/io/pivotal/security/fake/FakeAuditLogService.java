package io.pivotal.security.fake;

import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Primary;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@SuppressWarnings("unused")
@Component
@Primary
@ConditionalOnExpression(
    "#{!environment.getProperty('spring.profiles.active').contains('UseRealAuditLogService')}")
public class FakeAuditLogService implements AuditLogService {
  private AuditRecordBuilder auditRecordBuilder;

  @Override
  public ResponseEntity<?> performWithAuditing(ExceptionThrowingFunction<AuditRecordBuilder, ResponseEntity<?>, Exception> action) throws Exception {
    auditRecordBuilder = new AuditRecordBuilder();
    return action.apply(auditRecordBuilder);
  }

  public AuditRecordBuilder getAuditRecordBuilder() {
    return auditRecordBuilder;
  }
}
