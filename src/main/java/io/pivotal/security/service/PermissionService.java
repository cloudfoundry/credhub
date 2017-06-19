package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PermissionService {

  private PermissionsDataService permissionsDataService;

  @Value("${security.authorization.acls.enabled}")
  private boolean enforcePermissions;

  @Autowired
  public PermissionService(PermissionsDataService permissionsDataService) {
    this.permissionsDataService = permissionsDataService;
  }

  public boolean hasAclReadPermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      return permissionsDataService.hasReadAclPermission(actor, credentialName);
    } else {
      return true;
    }
  }

  public boolean hasAclWritePermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      return permissionsDataService.hasAclWritePermission(actor, credentialName);
    } else {
      return true;
    }
  }

  public boolean hasCredentialWritePermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      return permissionsDataService.hasCredentialWritePermission(actor, credentialName);
    } else {
      return true;
    }
  }

  public boolean hasCredentialReadPermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      return permissionsDataService.hasReadPermission(actor, credentialName);
    } else {
      return true;
    }
  }

  public boolean hasCredentialDeletePermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      return permissionsDataService.hasCredentialDeletePermission(actor, credentialName);
    } else {
      return true;
    }
  }

  private String getActorFromUserContext(UserContext user) {
    return user.getAclUser();
  }

  public boolean validAclUpdateOperation(UserContext userContext, String actor) {
    if (enforcePermissions) {
      return !userContext.getAclUser().equals(actor);
    } else {
      return true;
    }
  }
}
