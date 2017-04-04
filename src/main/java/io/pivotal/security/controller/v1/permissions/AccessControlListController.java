package io.pivotal.security.controller.v1.permissions;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.handler.AccessControlHandler;
import io.pivotal.security.view.AccessControlListResponse;
import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/acls", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class AccessControlListController {
  private final MessageSourceAccessor messageSourceAccessor;
  private final AccessControlHandler accessControlHandler;

  @Autowired
  public AccessControlListController(
      AccessControlHandler accessControlHandler,
      MessageSource messageSource
  ) {
    this.accessControlHandler = accessControlHandler;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @GetMapping
  public AccessControlListResponse getAccessControlList(
      @RequestParam("credential_name") String credentialName) {
    return accessControlHandler.getAccessControlListResponse(credentialName);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMissingParameterException(MissingServletRequestParameterException e) {
    return new ResponseError(messageSourceAccessor
        .getMessage("error.missing_query_parameter", new String[]{e.getParameterName()}));
  }

  @ExceptionHandler(JsonParseException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleJsonMappingException(JsonParseException e) {
    return badRequestResponse();
  }

  @ExceptionHandler(JsonMappingException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleJsonMappingException(JsonMappingException e) {
    for (JsonMappingException.Reference reference : e.getPath()) {
      if ("operations".equals(reference.getFieldName())) {
        String errorMessage = messageSourceAccessor.getMessage("error.acl.invalid_operation");
        return new ResponseError(errorMessage);
      }
    }

    return badRequestResponse();
  }

  @ExceptionHandler(EntryNotFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ResponseError handleNotFoundException(EntryNotFoundException e) {
    return constructError(e.getMessage());
  }

  private ResponseError constructError(String error) {
    return new ResponseError(messageSourceAccessor.getMessage(error));
  }

  private ResponseError badRequestResponse() {
    String errorMessage = messageSourceAccessor.getMessage("error.bad_request");
    return new ResponseError(errorMessage);
  }
}
