package io.pivotal.security.controller.v1;

import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class DefaultExceptionHandler {

  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  DefaultExceptionHandler(MessageSourceAccessor messageSourceAccessor) {
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(Exception.class)
  public ResponseError handleGeneralException()
      throws Exception {
    return new ResponseError(messageSourceAccessor.getMessage("error.internal_server_error"));
  }
}
