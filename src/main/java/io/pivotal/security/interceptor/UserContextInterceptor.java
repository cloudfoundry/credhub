package io.pivotal.security.interceptor;

import io.pivotal.security.auth.UserContextFactory;
import io.pivotal.security.auth.UserContextHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class UserContextInterceptor extends HandlerInterceptorAdapter {
  private final UserContextFactory userContextFactory;
  private final UserContextHolder userContextHolder;

  @Autowired
  UserContextInterceptor(
      UserContextFactory userContextFactory,
      UserContextHolder userContextHolder) {
    this.userContextFactory = userContextFactory;
    this.userContextHolder = userContextHolder;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    userContextHolder.setUserContext(userContextFactory.createUserContext(
        (Authentication) request.getUserPrincipal()));
    return super.preHandle(request, response, handler);
  }
}
