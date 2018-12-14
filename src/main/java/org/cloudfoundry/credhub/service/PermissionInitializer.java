package org.cloudfoundry.credhub.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.config.AuthorizationConfig;
import org.cloudfoundry.credhub.request.PermissionEntry;


@Component
public class PermissionInitializer {
  private final PermissionService permissionService;
  private final AuthorizationConfig authorizationConfig;

  @Autowired
  public PermissionInitializer(
    final PermissionService permissionService,
    final AuthorizationConfig authorizationConfig
  ) {
    super();
    this.permissionService = permissionService;
    this.authorizationConfig = authorizationConfig;
  }

  @EventListener(ContextRefreshedEvent.class)
  public void seed() {

    if (authorizationConfig == null || authorizationConfig.getPermissions() == null) {
      return;
    }

    for (final AuthorizationConfig.Permission permission : authorizationConfig.getPermissions()) {
      final List<PermissionEntry> permissionEntries = new ArrayList<>();
      for (final String actor : permission.getActors()) {
        permissionEntries.add(new PermissionEntry(actor, permission.getPath(), permission.getOperations()));
      }

      permissionService.savePermissions(permissionEntries);
    }
  }
}
