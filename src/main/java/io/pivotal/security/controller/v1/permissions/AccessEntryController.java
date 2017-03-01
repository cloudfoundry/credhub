package io.pivotal.security.controller.v1.permissions;

import static io.pivotal.security.controller.v1.permissions.AccessEntryController.API_V1_RESOURCES;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.service.AccessControlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping(path = API_V1_RESOURCES, produces = MediaType.APPLICATION_JSON_UTF8_VALUE, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class AccessEntryController {

  public static final String API_V1_RESOURCES = "/api/v1/resources";

  private AccessControlService accessControlService;

  @Autowired
  public AccessEntryController(AccessControlService accessControlService) {
    this.accessControlService = accessControlService;
  }

  @PostMapping(path = "/aces")
  public ResponseEntity setAccessControlEntry(@Validated @RequestBody AccessEntryRequest accessEntryRequest, Errors errors) {
    if (errors.hasErrors()) {
      Map error = constructError(errors);
      return wrapResponse(error, HttpStatus.BAD_REQUEST);
    } else {
      return wrapResponse(accessControlService.setAccessControlEntry(accessEntryRequest), HttpStatus.OK);
    }
  }

  private Map<String, String> constructError(Errors errors) {
    return Collections.singletonMap("error", errors.getAllErrors().get(0).getDefaultMessage());
  }

  private ResponseEntity wrapResponse(Object wrapped, HttpStatus status) {
    return new ResponseEntity<>(wrapped, status);
  }
}
