package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.view.ResponseError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class DefaultExceptionHandler {

  private final MessageSourceAccessor messageSourceAccessor;
  private final Logger logger;

  @Autowired
  DefaultExceptionHandler(MessageSourceAccessor messageSourceAccessor) {
    this.messageSourceAccessor = messageSourceAccessor;
    this.logger = LogManager.getLogger(this.getClass());
  }

  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(Exception.class)
  public ResponseError handleGeneralException(Exception e)
      throws Exception {
    String message = messageSourceAccessor.getMessage("error.internal_server_error");
    logger.error(message, e);
    return new ResponseError(message);
  }
}
