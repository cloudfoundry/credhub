package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.audit.EventAuditRecordParametersFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_DELETE;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_UPDATE;
import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;
import static java.util.Arrays.asList;

@Service
public class PermissionService {

  private PermissionDataService permissionDataService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;

  @Autowired
  public PermissionService(PermissionDataService permissionDataService,
      PermissionCheckingService permissionCheckingService,
      UserContextHolder userContextHolder) {
    this.permissionDataService = permissionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public List<PermissionOperation> getAllowedOperationsForLogging(String credentialName, String actor) {
    return permissionDataService.getAllowedOperations(credentialName, actor);
  }

  public void savePermissions(CredentialVersion credentialVersion,
      List<PermissionEntry> permissionEntryList,
      List<EventAuditRecordParameters> auditRecordParameters, boolean isNewCredential,
      String credentialName) {
    auditRecordParameters.addAll(EventAuditRecordParametersFactory
        .createPermissionsEventAuditParameters(ACL_UPDATE, credentialName, permissionEntryList));

    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    for (PermissionEntry permissionEntry : permissionEntryList) {
      if (!permissionCheckingService.userAllowedToOperateOnActor(permissionEntry.getActor())) {
        throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
      }
    }

    if (isNewCredential) {
      final PermissionEntry permissionEntry = new PermissionEntry(userContextHolder.getUserContext().getActor(), asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));
      permissionEntryList.add(permissionEntry);
      auditRecordParameters.addAll(
          EventAuditRecordParametersFactory.createPermissionsEventAuditParameters(ACL_UPDATE, credentialName, asList(permissionEntry)));
    }

    if (permissionEntryList.size() == 0) {
      return;
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialVersion.getName(), WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    permissionDataService.savePermissions(credentialVersion.getCredential(), permissionEntryList);
  }

  public List<PermissionEntry> getPermissions(CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters,
      String name) {
    auditRecordParameters.add(new EventAuditRecordParameters(ACL_ACCESS, name));

    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialVersion.getName(), READ_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return getPermissions(credentialVersion.getCredential());
  }

  public boolean deletePermissions(String credentialName, String actor, List<EventAuditRecordParameters> auditRecordParameters) {
    List<PermissionOperation> operationList = getAllowedOperationsForLogging(credentialName, actor);

    if (operationList.size() == 0) {
      auditRecordParameters.add(new EventAuditRecordParameters(ACL_DELETE, credentialName, null, actor));
    } else {
      auditRecordParameters.addAll(EventAuditRecordParametersFactory
          .createPermissionEventAuditRecordParameters(ACL_DELETE, credentialName, actor, operationList));
    }
    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!permissionCheckingService.userAllowedToOperateOnActor(actor)) {
      throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
    }

    return permissionDataService.deletePermissions(credentialName, actor);
  }

  private List<PermissionEntry> getPermissions(Credential credential) {
    return permissionDataService.getPermissions(credential);
  }
}
