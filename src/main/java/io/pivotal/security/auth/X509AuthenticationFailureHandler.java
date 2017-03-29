package io.pivotal.security.auth;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.view.ResponseError;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class X509AuthenticationFailureHandler implements AuthenticationFailureHandler {
  private static final String INVALID_DN_MESSAGE = "No matching pattern was found in subjectDN";
  private static final String INVALID_MTLS_ID_RESPONSE = "error.auth.invalid_mtls_identity";

  private final ObjectMapper objectMapper;
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  X509AuthenticationFailureHandler(
      MessageSource messageSource,
      ObjectMapper objectMapper
  ) {
    this.objectMapper = objectMapper;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException exception
  ) throws IOException, ServletException {
    if (exception.getMessage().contains(INVALID_DN_MESSAGE)) {
      ResponseError responseError = new ResponseError(
          messageSourceAccessor.getMessage(INVALID_MTLS_ID_RESPONSE)
      );

      response.setStatus(HttpStatus.UNAUTHORIZED.value());
      response.setContentType(APPLICATION_JSON.getType());
      response.getWriter().write(objectMapper.writeValueAsString(responseError));
    }
  }
}
