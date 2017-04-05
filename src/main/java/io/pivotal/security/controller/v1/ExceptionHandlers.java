package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class ExceptionHandlers {
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  ExceptionHandlers(MessageSource messageSource) {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @ExceptionHandler(EntryNotFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  @ResponseBody
  public ResponseError handleNotFoundException(EntryNotFoundException e) {
    return constructError(e.getMessage());
  }

  @ExceptionHandler(JsonMappingException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseError handleJsonMappingException(JsonMappingException e) {
    for (com.fasterxml.jackson.databind.JsonMappingException.Reference reference : e.getPath()) {
      if ("operations".equals(reference.getFieldName())) {
        return constructError("error.acl.invalid_operation");
      }
    }

    return badRequestResponse();
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseError handleMissingParameterException(MissingServletRequestParameterException e) {
    return new ResponseError(messageSourceAccessor
        .getMessage("error.missing_query_parameter", new String[]{e.getParameterName()}));
  }

  @ExceptionHandler(JsonParseException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ResponseBody
  public ResponseError handleJsonMappingException() {
    return badRequestResponse();
  }

  private ResponseError badRequestResponse() {
    return constructError("error.bad_request");
  }

  private ResponseError constructError(String error) {
    return new ResponseError(messageSourceAccessor.getMessage(error));
  }
}
