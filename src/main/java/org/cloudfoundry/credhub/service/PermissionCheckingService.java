package org.cloudfoundry.credhub.service;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.request.PermissionOperation;

@Component
public class PermissionCheckingService {
  private final PermissionDataService permissionDataService;
  private final UserContextHolder userContextHolder;

  @Value("${security.authorization.acls.enabled}")
  private boolean enforcePermissions;

  @Autowired
  public PermissionCheckingService(final PermissionDataService permissionDataService,
                                   final UserContextHolder userContextHolder) {
    super();
    this.permissionDataService = permissionDataService;
    this.userContextHolder = userContextHolder;
  }

  public boolean hasPermission(final String user, final String credentialName, final PermissionOperation permission) {
    if (enforcePermissions) {
      return permissionDataService.hasPermission(user, credentialName, permission);
    }
    return true;
  }

  public boolean hasPermission(final String user, final UUID guid, final PermissionOperation permission) {
    if (enforcePermissions) {
      final PermissionData permissionData = permissionDataService.getPermission(guid);
      if (permissionData == null) {
        return false;
      }
      return permissionDataService.hasPermission(user, permissionData.getPath(), permission);
    }
    return true;
  }

  public boolean hasPermissions(final String user, final String path, final List<PermissionOperation> permissions) {
    for (final PermissionOperation permission : permissions) {
      if (!permissionDataService.hasPermission(user, path, permission)) {
        return false;
      }
    }
    return true;
  }

  public boolean userAllowedToOperateOnActor(final String actor) {
    if (enforcePermissions) {
      final UserContext userContext = userContextHolder.getUserContext();
      return actor != null &&
        userContext.getActor() != null &&
        !StringUtils.equals(userContext.getActor(), actor);
    } else {
      return true;
    }
  }

  public boolean userAllowedToOperateOnActor(final UUID guid) {
    if (enforcePermissions) {
      final UserContext userContext = userContextHolder.getUserContext();
      final String actor = permissionDataService.getPermission(guid).getActor();
      return actor != null &&
        userContext.getActor() != null &&
        !StringUtils.equals(userContext.getActor(), actor);
    } else {
      return true;
    }
  }

}
