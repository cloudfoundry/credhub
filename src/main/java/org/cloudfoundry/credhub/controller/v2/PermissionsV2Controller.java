package org.cloudfoundry.credhub.controller.v2;

import org.cloudfoundry.credhub.handler.PermissionsHandler;
import org.cloudfoundry.credhub.request.PermissionsV2PatchRequest;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping(path = "/api/v2/permissions", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class PermissionsV2Controller {
  private final PermissionsHandler permissionsHandler;

  public PermissionsV2Controller(PermissionsHandler permissionsHandler) {
    this.permissionsHandler = permissionsHandler;
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public PermissionsV2View setPermissions(@Validated @RequestBody PermissionsV2Request permissionsRequest) {
    return permissionsHandler.setV2Permissions(permissionsRequest);
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View getPermissions(@PathVariable String guid){
   return permissionsHandler.getPermissions(UUID.fromString(guid));
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View putPermissions(@Validated @RequestBody PermissionsV2Request permissionsRequest,
                                          @PathVariable String guid){
    return permissionsHandler.putPermissions(guid, permissionsRequest);
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.PATCH)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View patchPermissions(@Validated @RequestBody PermissionsV2PatchRequest request,
                                            @PathVariable String guid){
    return permissionsHandler.patchPermissions(guid, request.getOperations());
  }

}
