package io.pivotal.security.controller.v1;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
public class UserContextArgumentResolver implements HandlerMethodArgumentResolver {
  private final UserContextFactory userContextFactory;

  @Autowired
  public UserContextArgumentResolver(UserContextFactory userContextFactory) {
    this.userContextFactory = userContextFactory;
  }

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.getParameterType().equals(UserContext.class);
  }

  @Override
  public Object resolveArgument(MethodParameter parameter,
      ModelAndViewContainer mavContainer,
      NativeWebRequest webRequest,
      WebDataBinderFactory binderFactory
  ) throws Exception {
    return userContextFactory.createUserContext((Authentication) webRequest.getUserPrincipal());
  }
}
