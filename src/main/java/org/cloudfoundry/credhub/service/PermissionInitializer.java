package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.AuthorizationConfiguration;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;


@Component
public class PermissionInitializer {
  private PermissionService permissionService;
  private AuthorizationConfiguration authorization;
  private CredentialVersionDataService credentialVersionDataService;

  @Autowired
  public PermissionInitializer(
      PermissionService permissionService,
      AuthorizationConfiguration authorizationConfig,
      CredentialVersionDataService credentialVersionDataService
  ) {
    this.permissionService = permissionService;
    this.authorization = authorizationConfig;
    this.credentialVersionDataService = credentialVersionDataService;
  }

  @EventListener(ContextRefreshedEvent.class)
  public void seed() {
    if (authorization == null || authorization.getAuthorization() == null || authorization.getAuthorization().getPermissions() == null) {
      return;
    }

    for (AuthorizationConfiguration.Authorization.Permission permission : authorization.getAuthorization().getPermissions()) {
      CredentialVersion credentialVersion = credentialVersionDataService.findMostRecent(permission.getPath());
      ArrayList<PermissionEntry> permissionEntries = new ArrayList<>();
      for (String actor : permission.getActors()) {
        permissionEntries.add(new PermissionEntry(actor, permission.getOperations()));
      }

      if (credentialVersion == null) {
        throw new EntryNotFoundException("error.resource_not_found");
      }
      permissionService.savePermissions(credentialVersion, permissionEntries);
    }
  }
}
