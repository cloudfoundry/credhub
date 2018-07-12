package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.Permissions;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;


@Component
public class PermissionInitializer {
  private PermissionService permissionService;
  private Permissions permissions;
  private CredentialVersionDataService credentialVersionDataService;

  @Autowired
  public PermissionInitializer(
      PermissionService permissionService,
      Permissions authorizationConfig,
      CredentialVersionDataService credentialVersionDataService
  ) {
    this.permissionService = permissionService;
    this.permissions = authorizationConfig;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  @EventListener(ContextRefreshedEvent.class)
  public void seed() {

    if (permissions == null ||  permissions.getPermissions() == null) {
      return;
    }

    for (Permissions.Permission permission : permissions.getPermissions()) {
      ArrayList<PermissionEntry> permissionEntries = new ArrayList<>();
      for (String actor : permission.getActors()) {
        permissionEntries.add(new PermissionEntry(actor, permission.getPath(), permission.getOperations()));
      }

      permissionService.savePermissions(permissionEntries);
    }
  }
}
