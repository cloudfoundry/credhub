package org.cloudfoundry.credhub.helpers;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class FakeOauthTokenFilter implements Filter {

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {

  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    throws IOException, ServletException {
    HttpServletRequest servletRequest = (HttpServletRequest) request;
    String header = servletRequest.getHeader("Authorization");

    if (header == null) {
      throw new ServletException("Missing Authorization header");
    }

    Pattern p = Pattern.compile("Bearer .+");
    if (!p.matcher(header).matches()) {
      throw new ServletException("Missing auth token in Authorization header");
    }
    chain.doFilter(request, response);
  }


  @Override
  public void destroy() {

  }
}
