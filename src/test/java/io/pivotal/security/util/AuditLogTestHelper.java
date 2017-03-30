package io.pivotal.security.util;

import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import org.mockito.Mockito;

import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;

public class AuditLogTestHelper {

  public static void resetAuditLogMock(AuditLogService auditLogService,
                                       AuditRecordBuilder auditRecordBuilder) throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final ExceptionThrowingFunction action = invocation.getArgumentAt(0,
          ExceptionThrowingFunction.class);
      return action.apply(auditRecordBuilder);
    }).when(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
  }
}
