package org.cloudfoundry.credhub.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException;
import org.cloudfoundry.credhub.exceptions.ReadOnlyException;
import org.cloudfoundry.credhub.variables.ManagementVariables;

@Component
public class ManagementInterceptor extends HandlerInterceptorAdapter {

  public static final String MANAGEMENT_API = "/management";
  public static final String INTERPOLATE_API = "/interpolate";

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    if (request.getRequestURI().equals(MANAGEMENT_API)
      && !request.getRemoteAddr().equals(request.getLocalAddr())) {
      throw new InvalidRemoteAddressException();
    }

    if (ManagementVariables.readOnlyMode
      && !request.getMethod().equalsIgnoreCase(RequestMethod.GET.toString())
      && !request.getRequestURI().equals(MANAGEMENT_API)
      && !request.getRequestURI().equals(INTERPOLATE_API)) {
      throw new ReadOnlyException();
    }

    return true;
  }
}
