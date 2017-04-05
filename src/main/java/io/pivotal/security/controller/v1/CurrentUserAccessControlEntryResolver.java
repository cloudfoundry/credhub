package io.pivotal.security.controller.v1;

import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.request.AccessControlEntry;
import java.util.Arrays;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public class CurrentUserAccessControlEntryResolver implements HandlerMethodArgumentResolver {
  private final ResourceServerTokenServices tokenServices;

  public CurrentUserAccessControlEntryResolver(ResourceServerTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.getParameterType().equals(AccessControlEntry.class);
  }

  @Override
  public Object resolveArgument(MethodParameter parameter,
      ModelAndViewContainer mavContainer,
      NativeWebRequest webRequest,
      WebDataBinderFactory binderFactory) throws Exception {
    UserContext userContext =
            UserContext.fromAuthentication(((Authentication) webRequest.getUserPrincipal()), null, tokenServices);
    AccessControlEntry accessControlEntry = new AccessControlEntry(
        userContext.getAclUser(),
        Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));
    return accessControlEntry;
  }
}
