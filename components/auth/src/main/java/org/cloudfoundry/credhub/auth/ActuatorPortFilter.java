package org.cloudfoundry.credhub.auth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ActuatorPortFilter extends OncePerRequestFilter {

  @Value("${management.server.port}")
  private Integer port;

  @Override
  protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
    throws ServletException, IOException {
    if (request.getLocalPort() == port && !request.getRequestURI().equals("/health")) {
      response.setStatus(HttpStatus.NOT_FOUND.value());
    } else {
      filterChain.doFilter(request, response);
    }
  }
}
