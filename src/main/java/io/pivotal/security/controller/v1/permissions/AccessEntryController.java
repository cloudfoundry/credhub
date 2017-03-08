package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.service.AccessControlService;
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
public class AccessEntryController {

  public static final String API_V1 = "/api/v1";

  private AccessControlService accessControlService;
  private final MessageSourceAccessor messageSourceAccessor;

  @Autowired
  public AccessEntryController(
      AccessControlService accessControlService,
      MessageSource messageSource
  ) {
    this.accessControlService = accessControlService;
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
      return wrapResponse(accessControlService.setAccessControlEntry(accessEntryRequest), HttpStatus.OK);
    }
  }

  @GetMapping(path = "/acls")
  @SuppressWarnings("unused")
  ResponseEntity getAccessControlEntry(@RequestParam("credential_name") String credentialName) {
    final AccessControlListResponse accessControlEntries = accessControlService.getAccessControlEntries(credentialName);

    if (accessControlEntries == null) {
      return wrapResponse(constructError("error.resource_not_found"),
          HttpStatus.NOT_FOUND);
    }

    return wrapResponse(accessControlEntries, HttpStatus.OK);
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseError handleMissingParameterException(MissingServletRequestParameterException e) {
    String errorMessage = messageSourceAccessor.getMessage("error.missing_query_parameter", new String[]{e.getParameterName()});
    return new ResponseError(errorMessage);
  }

  private ResponseError constructError(String error) {
    return new ResponseError(messageSourceAccessor.getMessage(error));
  }

  private ResponseEntity wrapResponse(Object wrapped, HttpStatus status) {
    return new ResponseEntity<>(wrapped, status);
  }

  private String getErrorMessage(Errors errors) {
    return errors.getAllErrors().get(0).getDefaultMessage();
  }
}
