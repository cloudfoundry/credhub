package org.cloudfoundry.credhub.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.cloudfoundry.credhub.auth.X509AuthenticationProvider.CLIENT_AUTH_EXTENDED_KEY_USAGE;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON;

@Component
public class X509AuthenticationFailureHandler implements AuthenticationFailureHandler {
  private static final String INVALID_DN_MESSAGE = "No matching pattern was found in subjectDN";
  private static final String INVALID_MTLS_ID_RESPONSE = "error.auth.invalid_mtls_identity";
  private static final String INVALID_CLIENT_AUTH_RESPONSE = "error.auth.mtls_not_client_auth";

  private final ObjectMapper objectMapper;
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  X509AuthenticationFailureHandler(
      MessageSourceAccessor messageSourceAccessor,
      ObjectMapper objectMapper
  ) {
    this.objectMapper = objectMapper;
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException exception
  ) throws IOException, ServletException {
    if (exception.getMessage().contains(INVALID_DN_MESSAGE)) {
      writeUnauthorizedResponse(response, INVALID_MTLS_ID_RESPONSE);
    }

    if (exception.getMessage().contains("Certificate does not contain: " + CLIENT_AUTH_EXTENDED_KEY_USAGE)) {
      writeUnauthorizedResponse(response, INVALID_CLIENT_AUTH_RESPONSE);
    }
  }

  private void writeUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
    ResponseError responseError = new ResponseError(
        messageSourceAccessor.getMessage(message, new String[]{ "foo" })
    );

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(APPLICATION_JSON.getType());
    response.getWriter().write(objectMapper.writeValueAsString(responseError));
  }
}
