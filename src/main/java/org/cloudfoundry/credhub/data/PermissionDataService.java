package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.entity.V2Permission;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException;
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException;
import org.cloudfoundry.credhub.exceptions.PermissionInvalidPathAndActorException;
import org.cloudfoundry.credhub.repository.PermissionRepository;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

@Component
public class PermissionDataService {

  private final CredentialDataService credentialDataService;
  private PermissionRepository permissionRepository;
  private CEFAuditRecord auditRecord;

  @Autowired
  public PermissionDataService(
      PermissionRepository permissionRepository,
      CredentialDataService credentialDataService,
      CEFAuditRecord auditRecord
  ) {
    this.permissionRepository = permissionRepository;
    this.credentialDataService = credentialDataService;
    this.auditRecord = auditRecord;
  }

  public List<PermissionEntry> getPermissions(Credential credential) {
    return createViewsFromPermissionsFor(credential);
  }

  public PermissionData getPermission(UUID guid) {
    PermissionData data = permissionRepository.findByUuid(guid);
    auditRecord.setResource(data);
    return data;
  }

  public List<PermissionData> savePermissionsWithLogging(List<PermissionEntry> permissions){
    List<PermissionData> permissionDatas = savePermissions(permissions);
    auditRecord.addAllResources(permissionDatas);

    V2Permission requestDetails = new V2Permission(permissionDatas.get(0).getPath(),
        permissionDatas.get(0).getActor(), permissionDatas.get(0).generateAccessControlOperations(),
        OperationDeviceAction.ADD_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);
    return permissionDatas;
  }

  public List<PermissionData> savePermissions(List<PermissionEntry> permissions) {
    List<PermissionData> result = new ArrayList<>();
    for (PermissionEntry permission : permissions) {
      String path = permission.getPath();
      List<PermissionData> existingPermissions = permissionRepository.findAllByPath(path);
      result.add(upsertPermissions(path, existingPermissions, permission.getActor(),
          permission.getAllowedOperations()));
    }

    return result;
  }

  public List<PermissionOperation> getAllowedOperations(String name, String actor) {
    List<PermissionOperation> operations = newArrayList();
    PermissionData permissionData = permissionRepository.findByPathAndActor(name, actor);

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

  public boolean deletePermissions(String name, String actor) {
    auditRecord.setResource(permissionRepository.findByPathAndActor(name, actor));
    return permissionRepository.deleteByPathAndActor(name, actor) > 0;
  }

  public Set<String> findAllPathsByActor(String actor){
    Set<String> result = new HashSet<>();

    permissionRepository.findAllPathsForActorWithReadPermission(actor).forEach(i -> result.add(i));

    return result;
  }

  public boolean hasNoDefinedAccessControl(String name) {
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      return false;
    }
    return (permissionRepository.findAllByPath(name).size() == 0);
  }

  public boolean hasPermission(String user, String path, PermissionOperation requiredPermission) {
    for (PermissionData permissionData : permissionRepository.findByPathsAndActor(findAllPaths(path), user)) {
      if (permissionData.hasPermission(requiredPermission)) {
        return true;
      }
    }
    return false;
  }

  private PermissionData upsertPermissions(String path,
                                 List<PermissionData> accessEntries, String actor, List<PermissionOperation> operations) {
    PermissionData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new PermissionData(path, actor);
    }

    entry.enableOperations(operations);
    permissionRepository.saveAndFlush(entry);

    return entry;
  }

  private List<String> findAllPaths(String path) {
    List<String> result = new ArrayList<>();
    result.add(path);
    for (int i = 0; i < path.length(); i++) {
      if (path.charAt(i) == '/') {
        result.add(path.substring(0, i + 1) + "*");
      }
    }

    return result;
  }

  private PermissionEntry createViewFor(PermissionData data) {
    if (data == null) {
      return null;
    }
    PermissionEntry entry = new PermissionEntry();
    List<PermissionOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setPath(data.getPath());
    entry.setActor(data.getActor());
    return entry;
  }

  private List<PermissionEntry> createViewsFromPermissionsFor(Credential credential) {
    List<PermissionData> data = permissionRepository.findAllByPath(credential.getName());
    auditRecord.addAllResources(data);

    return data.stream().map(this::createViewFor).collect(Collectors.toList());
  }

  private PermissionData findAccessEntryForActor(List<PermissionData> accessEntries,
                                                 String actor) {
    Optional<PermissionData> temp = accessEntries.stream()
        .filter(permissionData -> permissionData.getActor().equals(actor))
        .findFirst();
    return temp.orElse(null);
  }

  public boolean permissionExists(String user, String path) {
    return permissionRepository.findByPathAndActor(path, user) != null;
  }

  public PermissionData putPermissions(String guid, PermissionsV2Request permissionsRequest) {
    PermissionData existingPermissionData = null;

    try{
      existingPermissionData = permissionRepository.findByUuid(UUID.fromString(guid));
    }catch (IllegalArgumentException e){
      if(e.getMessage().startsWith("Invalid UUID string:")){
        throw new PermissionDoesNotExistException("error.permission.does_not_exist");
      }
    }
    if (existingPermissionData == null) {
      throw new PermissionDoesNotExistException("error.permission.does_not_exist");
    }

    if(!(existingPermissionData.getPath().equals(permissionsRequest.getPath()) &&
          existingPermissionData.getActor().equals(permissionsRequest.getActor()))){
      throw new PermissionInvalidPathAndActorException("error.permission.wrong_path_and_actor");
    }


    PermissionData permissionData = new PermissionData(permissionsRequest.getPath(),
        permissionsRequest.getActor(), permissionsRequest.getOperations());

    permissionData.setUuid(existingPermissionData.getUuid());
    permissionRepository.save(permissionData);
    auditRecord.setResource(permissionData);

    V2Permission requestDetails = new V2Permission(permissionData.getPath(),
        permissionData.getActor(), permissionData.generateAccessControlOperations(),
        OperationDeviceAction.PUT_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);

    return permissionData;
  }

  public PermissionData patchPermissions(String guid, List<PermissionOperation> operations) {
    PermissionData existingPermissionData = null;

    existingPermissionData = permissionRepository.findByUuid(UUID.fromString(guid));

    if (existingPermissionData == null) {
      throw new PermissionDoesNotExistException("error.permission.does_not_exist");
    }

    PermissionData patchedRecord = new PermissionData(existingPermissionData.getPath(),
        existingPermissionData.getActor(), operations);
    patchedRecord.setUuid(existingPermissionData.getUuid());

    permissionRepository.save(patchedRecord);
    auditRecord.setResource(patchedRecord);

    V2Permission requestDetails = new V2Permission(patchedRecord.getPath(),
        patchedRecord.getActor(), patchedRecord.generateAccessControlOperations(),
        OperationDeviceAction.PATCH_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);

    return patchedRecord;
  }

  public PermissionData saveV2Permissions(PermissionsV2Request permissionsRequest) {
    PermissionData existingPermissionData = permissionRepository.findByPathAndActor(permissionsRequest.getPath(),
        permissionsRequest.getActor());

    if (existingPermissionData != null) {
      throw new PermissionAlreadyExistsException("error.permission.already_exists");
    }

    PermissionData record = new PermissionData();
    record.setPath(permissionsRequest.getPath());
    record.setActor(permissionsRequest.getActor());
    record.enableOperations(permissionsRequest.getOperations());

    permissionRepository.save(record);

    auditRecord.setResource(record);

    V2Permission requestDetails = new V2Permission(record.getPath(), record.getActor(),
        record.generateAccessControlOperations(), OperationDeviceAction.ADD_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);

    return record;
  }

  public PermissionData deletePermissions(UUID guid) {
    PermissionData existingPermission = permissionRepository.findByUuid(guid);
    permissionRepository.delete(existingPermission);

    V2Permission requestDetails = new V2Permission(existingPermission.getPath(),
        existingPermission.getActor(), existingPermission.generateAccessControlOperations(),
        OperationDeviceAction.DELETE_PERMISSIONS);
    auditRecord.setRequestDetails(requestDetails);
    auditRecord.setResource(existingPermission);

    return existingPermission;
  }
}
