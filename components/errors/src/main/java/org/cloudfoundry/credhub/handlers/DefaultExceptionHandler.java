package org.cloudfoundry.credhub.handlers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.views.ResponseError;

@RestControllerAdvice
public class DefaultExceptionHandler {

  private final MessageSourceAccessor messageSourceAccessor;
  private static final Logger LOGGER = LogManager.getLogger(DefaultExceptionHandler.class);

  @Autowired
  public DefaultExceptionHandler(final MessageSourceAccessor messageSourceAccessor) {
    super();
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(Exception.class)
  public ResponseError handleGeneralException(final Exception e) {
    final String message = messageSourceAccessor.getMessage("error.internal_server_error");
    LOGGER.error(message, e.getClass());
    LOGGER.error(message, e);
    return new ResponseError(message);
  }
}
