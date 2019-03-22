package org.cloudfoundry.credhub.permissions;

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

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entities.AddPermission;
import org.cloudfoundry.credhub.audit.entities.DeletePermissions;
import org.cloudfoundry.credhub.audit.entities.GetPermissions;
import org.cloudfoundry.credhub.testdoubles.PermissionsHandler;
import org.cloudfoundry.credhub.requests.PermissionsRequest;
import org.cloudfoundry.credhub.views.PermissionsView;

@RestController
@RequestMapping(path = "/api/v1/permissions", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class PermissionsController {

  private final PermissionsHandler permissionsHandler;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public PermissionsController(final PermissionsHandler permissionsHandler, final CEFAuditRecord auditRecord) {
    super();
    this.permissionsHandler = permissionsHandler;
    this.auditRecord = auditRecord;
  }

  @GetMapping
  @ResponseStatus(HttpStatus.OK)
  public PermissionsView getAccessControlList(@RequestParam("credential_name") final String credentialName) {
    final String credentialNameWithLeadingSlash = StringUtils.prependIfMissing(credentialName, "/");
    auditRecord.setRequestDetails(new GetPermissions(credentialName));

    return permissionsHandler.getPermissions(credentialNameWithLeadingSlash);
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public void setAccessControlEntries(@Validated @RequestBody final PermissionsRequest accessEntriesRequest) {
    final AddPermission addPermission = new AddPermission(accessEntriesRequest.getCredentialName(),
      accessEntriesRequest.getPermissions());
    auditRecord.setRequestDetails(addPermission);
    permissionsHandler.writePermissions(accessEntriesRequest);
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteAccessControlEntry(
    @RequestParam("credential_name") final String credentialName,
    @RequestParam("actor") final String actor
  ) {
    final String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    final DeletePermissions deletePermissions = new DeletePermissions(credentialName, actor);
    auditRecord.setRequestDetails(deletePermissions);

    permissionsHandler.deletePermissionEntry(credentialNameWithPrependedSlash, actor);
  }
}
