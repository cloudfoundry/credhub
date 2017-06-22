package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.request.PermissionOperation;
import org.apache.commons.lang3.StringUtils;
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

  public boolean hasPermission(String user, String credentialName, PermissionOperation permission) {
    if (enforcePermissions) {
      if(permissionsDataService.hasNoDefinedAccessControl(credentialName)){
        return true;
      }
      return permissionsDataService.hasPermission(user, credentialName, permission);
    }
    return true;
  }

  public boolean validAclUpdateOperation(UserContext userContext, String actor) {
    if (enforcePermissions) {
      return actor != null &&
          userContext.getAclUser() != null &&
          !StringUtils.equals(userContext.getAclUser(), actor);
    } else {
      return true;
    }
  }
}
