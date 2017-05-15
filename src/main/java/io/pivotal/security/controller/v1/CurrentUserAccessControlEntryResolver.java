package io.pivotal.security.controller.v1;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextFactory;
import io.pivotal.security.request.PermissionEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.Arrays;

import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;

@Component
public class CurrentUserAccessControlEntryResolver implements HandlerMethodArgumentResolver {
  private final UserContextFactory userContextFactory;

  @Autowired
  public CurrentUserAccessControlEntryResolver(UserContextFactory userContextFactory) {
    this.userContextFactory = userContextFactory;
  }

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.getParameterType().equals(PermissionEntry.class);
  }

  @Override
  public Object resolveArgument(MethodParameter parameter,
      ModelAndViewContainer mavContainer,
      NativeWebRequest webRequest,
      WebDataBinderFactory binderFactory) throws Exception {
    UserContext userContext = userContextFactory.createUserContext((Authentication) webRequest.getUserPrincipal());
    return new PermissionEntry(
        userContext.getAclUser(),
        Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));
  }
}
