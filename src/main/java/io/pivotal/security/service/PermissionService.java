package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.exceptions.PermissionException;
import org.apache.commons.lang.StringUtils;
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

  public void verifyAclReadPermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      if (StringUtils.isEmpty(actor) || !permissionsDataService
          .hasReadAclPermission(actor, credentialName)) {
        throw new PermissionException("error.acl.lacks_acl_read");
      }
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

  public void verifyCredentialWritePermission(UserContext user, String credentialName) {
    if (enforcePermissions) {
      String actor = getActorFromUserContext(user);
      if (StringUtils.isEmpty(actor) || !permissionsDataService
          .hasCredentialWritePermission(actor, credentialName)) {
        throw new PermissionException("error.acl.lacks_credential_write");
      }
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
