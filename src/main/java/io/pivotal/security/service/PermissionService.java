package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionDataService;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidPermissionOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionEventAuditRecordParameters;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static java.util.Arrays.asList;

@Service
public class PermissionService {

  private PermissionDataService permissionDataService;
  private PermissionCheckingService permissionCheckingService;

  @Autowired
  public PermissionService(PermissionDataService permissionDataService, PermissionCheckingService permissionCheckingService) {
    this.permissionDataService = permissionDataService;
    this.permissionCheckingService = permissionCheckingService;
  }

  public List<PermissionOperation> getAllowedOperationsForLogging(String credentialName, String actor) {
    return permissionDataService.getAllowedOperations(credentialName, actor);
  }

  public void savePermissions(UserContext userContext, CredentialVersion credentialVersion, List<PermissionEntry> permissionEntryList, List<EventAuditRecordParameters> auditRecordParameters, boolean isNewCredential, String credentialName) {
    auditRecordParameters.addAll(createPermissionsEventAuditParameters(ACL_UPDATE, credentialName, permissionEntryList));

    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    for (PermissionEntry permissionEntry : permissionEntryList) {
      if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, permissionEntry.getActor())) {
        throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
      }
    }

    if (isNewCredential) {
      final PermissionEntry permissionEntry = new PermissionEntry(userContext.getActor(), asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));
      permissionEntryList.add(permissionEntry);
      auditRecordParameters.addAll(createPermissionsEventAuditParameters(ACL_UPDATE, credentialName, asList(permissionEntry)));
    }

    if (permissionEntryList.size() == 0) {
      return;
    }

    if (!permissionCheckingService.hasPermission(userContext.getActor(), credentialVersion.getName(), WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    permissionDataService.savePermissions(credentialVersion.getCredential(), permissionEntryList);
  }

  public List<PermissionEntry> getPermissions(UserContext userContext, CredentialVersion credentialVersion, List<EventAuditRecordParameters> auditRecordParameters, String name) {
    auditRecordParameters.add(new EventAuditRecordParameters(ACL_ACCESS, name));

    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    if (!permissionCheckingService.hasPermission(userContext.getActor(), credentialVersion.getName(), READ_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return getPermissions(credentialVersion.getCredential());
  }

  public boolean deletePermissions(UserContext userContext, String credentialName, String actor, List<EventAuditRecordParameters> auditRecordParameters) {
    List<PermissionOperation> operationList = getAllowedOperationsForLogging(credentialName, actor);

    if (operationList.size() == 0) {
      auditRecordParameters.add(new EventAuditRecordParameters(ACL_DELETE, credentialName, null, actor));
    } else {
      auditRecordParameters.addAll(createPermissionEventAuditRecordParameters(ACL_DELETE, credentialName, actor, operationList));
    }
    if (!permissionCheckingService
        .hasPermission(userContext.getActor(), credentialName, WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, actor)) {
      throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
    }

    return permissionDataService.deletePermissions(credentialName, actor);
  }

  private List<PermissionEntry> getPermissions(Credential credential) {
    return permissionDataService.getPermissions(credential);
  }
}
