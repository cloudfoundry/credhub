//package io.pivotal.security.audit;
//
//import java.io.IOException;
//import java.util.UUID;
//import javax.servlet.Filter;
//import javax.servlet.FilterChain;
//import javax.servlet.FilterConfig;
//import javax.servlet.ServletException;
//import javax.servlet.ServletRequest;
//import javax.servlet.ServletResponse;
//
//public class RequestUuidFilter implements Filter {
//  public static String REQUEST_UUID_ATTRIBUTE = "REQUEST_UUID";
//
//  @Override
//  public void init(FilterConfig filterConfig) throws ServletException {
//  }
//
//  @Override
//  public void doFilter(
//      ServletRequest request,
//      ServletResponse response,
//      FilterChain chain
//  ) throws IOException, ServletException {
//    request.setAttribute(REQUEST_UUID_ATTRIBUTE, UUID.randomUUID());
//    chain.doFilter(request, response);
//  }
//
//  @Override
//  public void destroy() {
//  }
//}
