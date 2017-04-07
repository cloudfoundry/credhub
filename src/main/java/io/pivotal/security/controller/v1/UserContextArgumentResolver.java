package io.pivotal.security.controller.v1;

import io.pivotal.security.auth.UserContext;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public class UserContextArgumentResolver implements HandlerMethodArgumentResolver {
  private final ResourceServerTokenServices tokenServices;

  public UserContextArgumentResolver(ResourceServerTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.getParameterType().equals(UserContext.class);
  }

  @Override
  public Object resolveArgument(MethodParameter parameter,
      ModelAndViewContainer mavContainer,
      NativeWebRequest webRequest,
      WebDataBinderFactory binderFactory) throws Exception {
    return UserContext.fromAuthentication((Authentication) webRequest.getUserPrincipal(), null, tokenServices);
  }
}
