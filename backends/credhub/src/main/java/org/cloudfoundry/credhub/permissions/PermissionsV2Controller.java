package org.cloudfoundry.credhub.permissions;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.generate.PermissionsHandler;
import org.cloudfoundry.credhub.requests.PermissionsV2PatchRequest;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.cloudfoundry.credhub.views.PermissionsV2View;

@RestController
@RequestMapping(path = PermissionsV2Controller.ENDPOINT, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class PermissionsV2Controller {

  public static final String ENDPOINT = "/api/v2/permissions";

  private final PermissionsHandler permissionsHandler;

  public PermissionsV2Controller(final PermissionsHandler permissionsHandler) {
    super();
    this.permissionsHandler = permissionsHandler;
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public PermissionsV2View postPermissions(@Validated @RequestBody final PermissionsV2Request permissionsRequest) {
    return permissionsHandler.writeV2Permissions(permissionsRequest);
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View getPermissions(@PathVariable final String guid) {
    return permissionsHandler.getPermissions(UUID.fromString(guid));
  }

  @RequestMapping(method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View findByPathAndActor(@RequestParam final String path, @RequestParam final String actor) {
    final String pathWithPrependedSlash = StringUtils.prependIfMissing(path, "/");

    return permissionsHandler.findByPathAndActor(pathWithPrependedSlash, actor);
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View putPermissions(@Validated @RequestBody final PermissionsV2Request permissionsRequest,
                                          @PathVariable final String guid) {
    return permissionsHandler.putPermissions(guid, permissionsRequest);
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.PATCH)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View patchPermissions(@Validated @RequestBody final PermissionsV2PatchRequest request,
                                            @PathVariable final String guid) {
    return permissionsHandler.patchPermissions(guid, request.getOperations());
  }

  @RequestMapping(path = "/{guid}", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsV2View deletePermissions(@PathVariable final String guid) {
    return permissionsHandler.deletePermissions(guid);
  }
}
