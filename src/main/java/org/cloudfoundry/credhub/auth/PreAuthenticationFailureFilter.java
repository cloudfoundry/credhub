package org.cloudfoundry.credhub.auth;

import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class PreAuthenticationFailureFilter extends OncePerRequestFilter {
  private final X509AuthenticationFailureHandler authenticationFailureHandler;

  PreAuthenticationFailureFilter(X509AuthenticationFailureHandler authenticationFailureHandler) {
    this.authenticationFailureHandler = authenticationFailureHandler;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain
  ) throws ServletException, IOException {
    try {
      filterChain.doFilter(request, response);
    } catch (AuthenticationException exception) {
      authenticationFailureHandler.onAuthenticationFailure(request, response, exception);
    }
  }
}
