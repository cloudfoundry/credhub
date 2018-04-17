package org.cloudfoundry.credhub.controller.v1;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.AddPermission;
import org.cloudfoundry.credhub.audit.entity.DeletePermissions;
import org.cloudfoundry.credhub.audit.entity.GetPermissions;
import org.cloudfoundry.credhub.handler.PermissionsHandler;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/permissions", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class PermissionsController {

  private final PermissionsHandler permissionsHandler;
  private CEFAuditRecord auditRecord;

  @Autowired
  public PermissionsController(PermissionsHandler permissionsHandler, CEFAuditRecord auditRecord) {
    this.permissionsHandler = permissionsHandler;
    this.auditRecord = auditRecord;
  }

  @GetMapping
  @ResponseStatus(HttpStatus.OK)
  public PermissionsView getAccessControlList(@RequestParam("credential_name") String credentialName) {
    String credentialNameWithLeadingSlash = StringUtils.prependIfMissing(credentialName, "/");
    auditRecord.setRequestDetails(new GetPermissions(credentialName));

    return permissionsHandler.getPermissions(credentialNameWithLeadingSlash);
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public void setAccessControlEntries(@Validated @RequestBody PermissionsRequest accessEntriesRequest) {

    AddPermission addPermission = new AddPermission(accessEntriesRequest.getCredentialName(),
        accessEntriesRequest.getPermissions());
    auditRecord.setRequestDetails(addPermission);
    permissionsHandler.setPermissions(accessEntriesRequest);
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteAccessControlEntry(
      @RequestParam("credential_name") String credentialName,
      @RequestParam("actor") String actor
  ) {
    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    DeletePermissions deletePermissions = new DeletePermissions(credentialName, actor);
    auditRecord.setRequestDetails(deletePermissions);

    permissionsHandler.deletePermissionEntry(credentialNameWithPrependedSlash, actor);
  }
}
