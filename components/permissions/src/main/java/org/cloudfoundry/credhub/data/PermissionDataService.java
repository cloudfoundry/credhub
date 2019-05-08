package org.cloudfoundry.credhub.data;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Lists;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.entities.V2Permission;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException;
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException;
import org.cloudfoundry.credhub.exceptions.PermissionInvalidPathAndActorException;
import org.cloudfoundry.credhub.repositories.PermissionRepository;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.cloudfoundry.credhub.services.CredentialDataService;

@SuppressWarnings("PMD.TooManyMethods")
@Component
@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "Let's refactor this class into kotlin"
)
public class PermissionDataService {

  private final CredentialDataService credentialDataService;
  private final PermissionRepository permissionRepository;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public PermissionDataService(
    final PermissionRepository permissionRepository,
    final CredentialDataService credentialDataService,
    final CEFAuditRecord auditRecord
  ) {
    super();
    this.permissionRepository = permissionRepository;
    this.credentialDataService = credentialDataService;
    this.auditRecord = auditRecord;
  }

  public List<PermissionEntry> getPermissions(final Credential credential) {
    return createViewsFromPermissionsFor(credential);
  }

  public PermissionData getPermission(final UUID guid) {
    final PermissionData data = permissionRepository.findByUuid(guid);
    auditRecord.setResource(data);
    return data;
  }

  public List<PermissionData> savePermissionsWithLogging(final List<PermissionEntry> permissions) {
    final List<PermissionData> permissionDatas = savePermissions(permissions);

    auditRecord.addAllResources(Lists.newArrayList(permissionDatas));

    final V2Permission requestDetails = new V2Permission(permissionDatas.get(0).getPath(),
      permissionDatas.get(0).getActor(), permissionDatas.get(0).generateAccessControlOperations(),
      OperationDeviceAction.ADD_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);
    return permissionDatas;
  }

  public List<PermissionData> savePermissions(final List<PermissionEntry> permissions) {
    final List<PermissionData> result = new ArrayList<>();
    for (final PermissionEntry permission : permissions) {
      final String path = permission.getPath();
      final List<PermissionData> existingPermissions = permissionRepository.findAllByPath(path);
      result.add(upsertPermissions(path, existingPermissions, permission.getActor(),
        permission.getAllowedOperations()));
    }

    return result;
  }

  public List<PermissionOperation> getAllowedOperations(final String name, final String actor) {
    final List<PermissionOperation> operations = Lists.newArrayList();
    final PermissionData permissionData = permissionRepository.findByPathAndActor(name, actor);

    if (permissionData != null) {
      if (permissionData.hasReadPermission()) {
        operations.add(PermissionOperation.READ);
      }
      if (permissionData.hasWritePermission()) {
        operations.add(PermissionOperation.WRITE);
      }
      if (permissionData.hasDeletePermission()) {
        operations.add(PermissionOperation.DELETE);
      }
      if (permissionData.hasReadAclPermission()) {
        operations.add(PermissionOperation.READ_ACL);
      }
      if (permissionData.hasWriteAclPermission()) {
        operations.add(PermissionOperation.WRITE_ACL);
      }
    }

    return operations;
  }

  public boolean deletePermissions(final String name, final String actor) {
    auditRecord.setResource(permissionRepository.findByPathAndActor(name, actor));
    return permissionRepository.deleteByPathAndActor(name, actor) > 0;
  }

  public Set<String> findAllPathsByActor(final String actor) {
    final Set<String> result = new HashSet<>();

    permissionRepository.findAllPathsForActorWithReadPermission(actor).forEach(i -> result.add(i));

    return result;
  }

  public boolean hasNoDefinedAccessControl(final String name) {
    final Credential credential = credentialDataService.find(name);
    if (credential == null) {
      return false;
    }
    return permissionRepository.findAllByPath(name).size() == 0;
  }

  public boolean hasPermission(final String user, final String path, final PermissionOperation requiredPermission) {
    for (final PermissionData permissionData : permissionRepository.findByPathsAndActor(findAllPaths(path), user)) {
      if (permissionData.hasPermission(requiredPermission)) {
        return true;
      }
    }
    return false;
  }

  private PermissionData upsertPermissions(final String path,
                                           final List<PermissionData> accessEntries, final String actor, final List<PermissionOperation> operations) {
    PermissionData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new PermissionData(path, actor);
    }

    entry.enableOperations(operations);
    permissionRepository.saveAndFlush(entry);

    return entry;
  }

  private List<String> findAllPaths(final String path) {
    final List<String> result = new ArrayList<>();
    result.add(path);

    final char pathSeparator = '/';

    for (int i = 0; i < path.length(); i++) {
      if (path.charAt(i) == pathSeparator) {
        result.add(path.substring(0, i + 1) + "*");
      }
    }

    return result;
  }

  private PermissionEntry createViewFor(final PermissionData data) {
    if (data == null) {
      return null;
    }
    final PermissionEntry entry = new PermissionEntry();
    final List<PermissionOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setPath(data.getPath());
    entry.setActor(data.getActor());
    return entry;
  }

  private List<PermissionEntry> createViewsFromPermissionsFor(final Credential credential) {
    final List<PermissionData> data = permissionRepository.findAllByPath(credential.getName());
    auditRecord.addAllResources(Lists.newArrayList(data));

    return data.stream().map(this::createViewFor).collect(Collectors.toList());
  }

  private PermissionData findAccessEntryForActor(final List<PermissionData> accessEntries,
                                                 final String actor) {
    final Optional<PermissionData> temp = accessEntries.stream()
      .filter(permissionData -> permissionData.getActor().equals(actor))
      .findFirst();
    return temp.orElse(null);
  }

  public boolean permissionExists(final String user, final String path) {
    return permissionRepository.findByPathAndActor(path, user) != null;
  }

  public PermissionData putPermissions(final String guid, final PermissionsV2Request permissionsRequest) {
    PermissionData existingPermissionData = null;

    try {
      existingPermissionData = permissionRepository.findByUuid(UUID.fromString(guid));
    } catch (final IllegalArgumentException e) {
      if (e.getMessage().startsWith("Invalid UUID string:")) {
        throw new PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST);
      }
    }
    if (existingPermissionData == null) {
      throw new PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST);
    }

    if (!(existingPermissionData.getPath().equals(permissionsRequest.getPath()) &&
      existingPermissionData.getActor().equals(permissionsRequest.getActor()))) {
      throw new PermissionInvalidPathAndActorException(ErrorMessages.Permissions.WRONG_PATH_AND_ACTOR);
    }


    final PermissionData permissionData = new PermissionData(permissionsRequest.getPath(),
      permissionsRequest.getActor(), permissionsRequest.getOperations());

    permissionData.setUuid(existingPermissionData.getUuid());
    permissionRepository.save(permissionData);
    auditRecord.setResource(permissionData);

    final V2Permission requestDetails = new V2Permission(permissionData.getPath(),
      permissionData.getActor(), permissionData.generateAccessControlOperations(),
      OperationDeviceAction.PUT_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);

    return permissionData;
  }

  public PermissionData patchPermissions(final String guid, final List<PermissionOperation> operations) {
    PermissionData existingPermissionData = null;

    existingPermissionData = permissionRepository.findByUuid(UUID.fromString(guid));

    if (existingPermissionData == null) {
      throw new PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST);
    }

    final PermissionData patchedRecord = new PermissionData(existingPermissionData.getPath(),
      existingPermissionData.getActor(), operations);
    patchedRecord.setUuid(existingPermissionData.getUuid());

    permissionRepository.save(patchedRecord);
    auditRecord.setResource(patchedRecord);

    final V2Permission requestDetails = new V2Permission(patchedRecord.getPath(),
      patchedRecord.getActor(), patchedRecord.generateAccessControlOperations(),
      OperationDeviceAction.PATCH_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);

    return patchedRecord;
  }

  public PermissionData saveV2Permissions(final PermissionsV2Request permissionsRequest) {
    final PermissionData existingPermissionData = permissionRepository.findByPathAndActor(permissionsRequest.getPath(),
      permissionsRequest.getActor());

    if (existingPermissionData != null) {
      throw new PermissionAlreadyExistsException(ErrorMessages.Permissions.ALREADY_EXISTS);
    }

    final PermissionData record = new PermissionData();
    record.setPath(permissionsRequest.getPath());
    record.setActor(permissionsRequest.getActor());
    record.enableOperations(permissionsRequest.getOperations());

    permissionRepository.save(record);

    auditRecord.setResource(record);

    final V2Permission requestDetails = new V2Permission(record.getPath(), record.getActor(),
      record.generateAccessControlOperations(), OperationDeviceAction.ADD_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);

    return record;
  }

  public PermissionData deletePermissions(final UUID guid) {
    final PermissionData existingPermission = permissionRepository.findByUuid(guid);
    permissionRepository.delete(existingPermission);

    final V2Permission requestDetails = new V2Permission(existingPermission.getPath(),
      existingPermission.getActor(), existingPermission.generateAccessControlOperations(),
      OperationDeviceAction.DELETE_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);
    auditRecord.setResource(existingPermission);

    return existingPermission;
  }

  public PermissionData findByPathAndActor(final String path, final String actor) {
    return permissionRepository.findByPathAndActor(path, actor);
  }
}
