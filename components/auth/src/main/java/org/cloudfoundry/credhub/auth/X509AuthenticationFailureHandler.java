package org.cloudfoundry.credhub.auth;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.views.ResponseError;

import static org.cloudfoundry.credhub.auth.X509AuthenticationProvider.CLIENT_AUTH_EXTENDED_KEY_USAGE;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON;

@Component
public class X509AuthenticationFailureHandler implements AuthenticationFailureHandler {
  private static final String INVALID_DN_MESSAGE = "No matching pattern was found in subjectDN";
  private static final String INVALID_MTLS_ID_RESPONSE = ErrorMessages.Auth.INVALID_MTLS_IDENTITY;
  private static final String INVALID_CLIENT_AUTH_RESPONSE = ErrorMessages.Auth.MTLS_NOT_CLIENT_AUTH;

  private final ObjectMapper objectMapper;

  @Autowired
  X509AuthenticationFailureHandler(
    final ObjectMapper objectMapper
  ) {
    super();
    this.objectMapper = objectMapper;
  }

  @Override
  public void onAuthenticationFailure(
    final HttpServletRequest request,
    final HttpServletResponse response,
    final AuthenticationException exception
  ) throws IOException {
    if (exception.getMessage().contains(INVALID_DN_MESSAGE)) {
      writeUnauthorizedResponse(response, INVALID_MTLS_ID_RESPONSE);
    }

    if (exception.getMessage().contains("Certificate does not contain: " + CLIENT_AUTH_EXTENDED_KEY_USAGE)) {
      writeUnauthorizedResponse(response, INVALID_CLIENT_AUTH_RESPONSE);
    }
  }

  private void writeUnauthorizedResponse(final HttpServletResponse response, final String message) throws IOException {
    final ResponseError responseError = new ResponseError(message);

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(APPLICATION_JSON.getType());
    response.getWriter().write(objectMapper.writeValueAsString(responseError));
  }
}
