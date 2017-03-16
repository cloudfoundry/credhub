package io.pivotal.security.controller.v1.permissions;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.view.AccessControlListResponse;
import io.pivotal.security.view.ResponseError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static io.pivotal.security.controller.v1.permissions.AccessEntryController.API_V1;

@RestController
@RequestMapping(path = API_V1, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
@SuppressWarnings("unused")
public class AccessEntryController {

  public static final String API_V1 = "/api/v1";

  private AccessControlDataService accessControlDataService;
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  public AccessEntryController(
      AccessControlDataService accessControlDataService,
      MessageSource messageSource
  ) {
    this.accessControlDataService = accessControlDataService;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @PostMapping(path = "/aces", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  ResponseEntity setAccessControlEntry(
      @Validated @RequestBody AccessEntryRequest accessEntryRequest,
      Errors errors
  ) {
    if (errors.hasErrors()) {
      ResponseError error = constructError(getErrorMessage(errors));
      return wrapResponse(error, HttpStatus.BAD_REQUEST);
    } else {
      return wrapResponse(accessControlDataService.setAccessControlEntry(accessEntryRequest), HttpStatus.OK);
    }
  }

  @GetMapping(path = "/acls")
  AccessControlListResponse getAccessControlList(@RequestParam("credential_name") String credentialName) {
    return accessControlDataService.getAccessControlListResponse(credentialName);
  }

  @DeleteMapping(path="/aces")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void deleteAccessControlEntry (
      @RequestParam("credential_name") String credentialName,
      @RequestParam("actor") String actor
  ) {
    accessControlDataService.deleteAccessControlEntry(credentialName, actor);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  private ResponseError handleMissingParameterException(MissingServletRequestParameterException e) {
    return new ResponseError(messageSourceAccessor.getMessage("error.missing_query_parameter", new String[]{e.getParameterName()}));
  }

  @ExceptionHandler(JsonParseException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  private ResponseError handleJsonMappingException(JsonParseException e) {
    return badRequestResponse();
  }

  @ExceptionHandler(JsonMappingException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  private ResponseError handleJsonMappingException(JsonMappingException e) {
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
  private ResponseError handleNotFoundException(EntryNotFoundException e){
    return constructError(e.getMessage());
  }

  private ResponseError constructError(String error) {
    return new ResponseError(messageSourceAccessor.getMessage(error));
  }

  private ResponseEntity wrapResponse(Object wrapped, HttpStatus status) {
    return new ResponseEntity<>(wrapped, status);
  }

  private ResponseError badRequestResponse() {
    String errorMessage = messageSourceAccessor.getMessage("error.bad_request");
    return new ResponseError(errorMessage);
  }

  private String getErrorMessage(Errors errors) {
    return errors.getAllErrors().get(0).getDefaultMessage();
  }
}
