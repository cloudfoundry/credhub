package org.cloudfoundry.credhub.service;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.config.Permissions;
import org.cloudfoundry.credhub.request.PermissionEntry;


@Component
public class PermissionInitializer {
  private PermissionService permissionService;
  private Permissions permissions;

  @Autowired
  public PermissionInitializer(
    PermissionService permissionService,
    Permissions authorizationConfig
  ) {
    this.permissionService = permissionService;
    this.permissions = authorizationConfig;
  }

  @EventListener(ContextRefreshedEvent.class)
  public void seed() {

    if (permissions == null || permissions.getPermissions() == null) {
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
