package io.pivotal.security.interceptor;

import io.pivotal.security.config.AuditLogConfigurationTest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@SuppressWarnings("unused")
@Component
@Primary
@ConditionalOnMissingBean(AuditLogConfigurationTest.TestConfiguration.class)
public class FakeAuditLogInterceptor extends HandlerInterceptorAdapter implements AuditLogInterceptor {
  // This test-only-bean is used to disable audit log database hits to speed up tests
}
