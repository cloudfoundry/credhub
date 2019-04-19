package org.cloudfoundry.credhub.generate;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.views.ResponseError;

@RestControllerAdvice
public class DefaultExceptionHandler {

  private static final Logger LOGGER = LogManager.getLogger(DefaultExceptionHandler.class);

  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(Exception.class)
  public ResponseError handleGeneralException(final Exception e) {
    final String message = ErrorMessages.INTERNAL_SERVER_ERROR;
    LOGGER.error(message, e.getClass());
    LOGGER.error(message, e);
    return new ResponseError(message);
  }
}
