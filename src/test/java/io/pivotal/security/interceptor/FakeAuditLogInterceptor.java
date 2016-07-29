package io.pivotal.security.interceptor;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@Component
@Primary
public class FakeAuditLogInterceptor extends HandlerInterceptorAdapter implements AuditLogInterceptor {
}
