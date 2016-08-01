package io.pivotal.security.interceptor;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@SuppressWarnings("unused")
@Component
@Primary
@ConditionalOnExpression("#{!environment.getProperty('spring.profiles.active').contains('AuditLogConfigurationTest')}")
public class FakeAuditLogInterceptor extends HandlerInterceptorAdapter implements AuditLogInterceptor {
  // This test-only-bean is used to disable audit log database hits to speed up tests
}
