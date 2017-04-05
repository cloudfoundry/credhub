package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.handler.AccessControlHandler;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/aces", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class AccessControlEntryController {

  private AccessControlHandler accessControlHandler;

  @Autowired
  public AccessControlEntryController(AccessControlHandler accessControlHandler) {
    this.accessControlHandler = accessControlHandler;
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public AccessControlListResponse setAccessControlEntries(
      @Validated @RequestBody AccessEntriesRequest accessEntriesRequest
  ) {
    return accessControlHandler.setAccessControlEntries(accessEntriesRequest);
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteAccessControlEntries(
      @RequestParam("credential_name") String credentialName,
      @RequestParam("actor") String actor
  ) {
    accessControlHandler.deleteAccessControlEntries(credentialName, actor);
  }
}
