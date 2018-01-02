package org.cloudfoundry.credhub.controller.v1;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.jayway.jsonpath.InvalidJsonException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.exceptions.AuditSaveFailureException;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.InvalidObjectException;

import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;

@RestControllerAdvice
@Order(HIGHEST_PRECEDENCE)
public class ExceptionHandlers {
  private final MessageSourceAccessor messageSourceAccessor;
  private final Logger logger;

  @Autowired
  ExceptionHandlers(MessageSourceAccessor messageSourceAccessor) {
    this.messageSourceAccessor = messageSourceAccessor;
    this.logger = LogManager.getLogger(this.getClass());
  }

  @ExceptionHandler(EntryNotFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseError handleNotFoundException(EntryNotFoundException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public void handleRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) {}

  @ExceptionHandler(PermissionException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseError handlePermissionException(PermissionException error) {
    return constructError(error.getMessage());
  }

  @ExceptionHandler(JsonMappingException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleJsonMappingException(JsonMappingException e) {
    for (com.fasterxml.jackson.databind.JsonMappingException.Reference reference : e.getPath()) {
      if ("operations".equals(reference.getFieldName())) {
        return constructError("error.permission.invalid_operation");
      }
    }

    return badRequestResponse();
  }

  @ExceptionHandler(InvalidQueryParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidParameterException(InvalidQueryParameterException e) {
    return constructError(e.getMessage(), e.getInvalidQueryParameter());
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMissingParameterException(MissingServletRequestParameterException e) {
    return constructError("error.missing_query_parameter", e.getParameterName());
  }

  @ExceptionHandler(JsonParseException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleJsonMappingException(JsonParseException e) {
    return badRequestResponse();
  }

  @ExceptionHandler(ParameterizedValidationException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleParameterizedValidationException(
      ParameterizedValidationException exception
  ) {
    return constructError(exception.getMessage(), exception.getParameters());
  }

  @ExceptionHandler(UnrecognizedPropertyException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleUnrecognizedPropertyException(UnrecognizedPropertyException exception) {
    return constructError("error.invalid_json_key", exception.getPropertyName());
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleMethodArgumentNotValidException(MethodArgumentNotValidException exception) {
    return constructError(exception.getBindingResult().getAllErrors().get(0).getDefaultMessage());
  }

  @ExceptionHandler({HttpMessageNotReadableException.class, InvalidJsonException.class, InvalidFormatException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInputNotReadableException(Exception exception) {
    final Throwable cause = exception.getCause() == null ? exception : exception.getCause();
    if (cause instanceof UnrecognizedPropertyException) {
      return constructError("error.invalid_json_key", ((UnrecognizedPropertyException) cause).getPropertyName());
    } else if (cause instanceof InvalidTypeIdException
        || (cause instanceof JsonMappingException && cause.getMessage()
        .contains("missing property 'type'"))) {
      return constructError("error.invalid_type_with_set_prompt");
    } else if (cause instanceof InvalidFormatException) {
      for (InvalidFormatException.Reference reference : ((InvalidFormatException) cause)
          .getPath()) {
        if ("operations".equals(reference.getFieldName())) {
          return constructError("error.permission.invalid_operation");
        }
      }
    }
    return badRequestResponse();
  }

  @ExceptionHandler(InvalidPermissionOperationException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleIncorrectAclOperation(InvalidPermissionOperationException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(AuditSaveFailureException.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseError handleAuditSaveFailureException(AuditSaveFailureException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(KeyNotFoundException.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseError handleKeyNotFoundException(KeyNotFoundException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(InvalidObjectException.class)
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidTypeAccess(InvalidObjectException exception) {
    return constructError(exception.getMessage());
  }

  private ResponseError badRequestResponse() {
    return constructError("error.bad_request");
  }

  private ResponseError constructError(String error) {

    String message = messageSourceAccessor.getMessage(error);
    logger.error(message);
    return new ResponseError(message);
  }

  private ResponseError constructError(String error, String... args) {
    String message = messageSourceAccessor.getMessage(error, args);
    logger.error(message);
    return new ResponseError(message);
  }

  private ResponseError constructError(String error, Object[] args) {
    String message = messageSourceAccessor.getMessage(error, args);
    logger.error(message);
    return new ResponseError(message);
  }
}
