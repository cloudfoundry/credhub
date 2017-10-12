package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionDataService;
import io.pivotal.security.request.PermissionOperation;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class PermissionCheckingService {
  private PermissionDataService permissionDataService;

  @Value("${security.authorization.acls.enabled}")
  private boolean enforcePermissions;

  @Autowired
  public PermissionCheckingService(PermissionDataService permissionDataService) {
    this.permissionDataService = permissionDataService;
  }

  public boolean hasPermission(String user, String credentialName, PermissionOperation permission) {
    if (enforcePermissions) {
      if (permissionDataService.hasNoDefinedAccessControl(credentialName)) {
        return true;
      }
      return permissionDataService.hasPermission(user, credentialName, permission);
    }
    return true;
  }

  public boolean userAllowedToOperateOnActor(UserContext userContext, String actor) {
    if (enforcePermissions) {
      return actor != null &&
          userContext.getActor() != null &&
          !StringUtils.equals(userContext.getActor(), actor);
    } else {
      return true;
    }
  }

}
