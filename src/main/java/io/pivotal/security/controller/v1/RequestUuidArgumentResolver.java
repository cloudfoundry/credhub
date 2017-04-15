package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.RequestUuid;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.UUID;

import static io.pivotal.security.audit.AuditInterceptor.REQUEST_UUID_ATTRIBUTE;

@Component
public class RequestUuidArgumentResolver implements HandlerMethodArgumentResolver {
  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.getParameterType().equals(RequestUuid.class);
  }

  @Override
  public Object resolveArgument(MethodParameter parameter,
                                ModelAndViewContainer mavContainer,
                                NativeWebRequest webRequest,
                                WebDataBinderFactory binderFactory
  ) throws Exception {
    return new RequestUuid((UUID) webRequest.getAttribute(REQUEST_UUID_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
  }
}
