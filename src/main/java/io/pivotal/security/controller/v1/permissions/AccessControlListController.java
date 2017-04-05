package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.handler.AccessControlHandler;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/acls", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class AccessControlListController {
  private final AccessControlHandler accessControlHandler;

  @Autowired
  public AccessControlListController(AccessControlHandler accessControlHandler) {
    this.accessControlHandler = accessControlHandler;
  }

  @GetMapping
  public AccessControlListResponse getAccessControlList(
      @RequestParam("credential_name") String credentialName
  ) {
    return accessControlHandler.getAccessControlListResponse(credentialName);
  }
}
