package org.cloudfoundry.credhub.interceptors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.cloudfoundry.credhub.auth.UserContextHolder;

@Component
public class UserContextInterceptor extends HandlerInterceptorAdapter {
  private final UserContextFactory userContextFactory;
  private final UserContextHolder userContextHolder;

  @Autowired
  UserContextInterceptor(
    final UserContextFactory userContextFactory,
    final UserContextHolder userContextHolder) {
    super();
    this.userContextFactory = userContextFactory;
    this.userContextHolder = userContextHolder;
  }

  @Override
  public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) {
    final Authentication principal = (Authentication) request.getUserPrincipal();
    if (principal == null) {
      return false;
    }
    userContextHolder.setUserContext(userContextFactory.createUserContext(principal));
    return true;
  }
}
