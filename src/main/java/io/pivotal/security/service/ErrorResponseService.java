package io.pivotal.security.service;

import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.stereotype.Service;

@Service
public class ErrorResponseService {
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  public ErrorResponseService(MessageSource messageSource) {
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  public ResponseError createErrorResponse(String key) {
    return createParameterizedErrorResponse(new ParameterizedValidationException(key));
  }

  public ResponseError createParameterizedErrorResponse(ParameterizedValidationException exception) {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseError(errorMessage);
  }
}
