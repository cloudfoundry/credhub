package org.cloudfoundry.credhub.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import org.cloudfoundry.credhub.PermissionOperation;

@Configuration
@ConfigurationProperties("security.authorization")
public class AuthorizationConfig {
  private List<Permission> permissions;

  public List<Permission> getPermissions() {
    return permissions;
  }

  public void setPermissions(final List<Permission> permissions) {
    this.permissions = permissions;
  }

  public static class Permission {
    private List<String> actors;
    private List<PermissionOperation> operations;
    private String path;

    public String getPath() {
      return path;
    }

    public void setPath(final String path) {
      this.path = path;
    }

    public List<String> getActors() {
      return actors;
    }

    public void setActors(final List<String> actors) {
      this.actors = actors;
    }

    public List<PermissionOperation> getOperations() {
      return operations;
    }

    public void setOperations(final List<PermissionOperation> operations) {
      this.operations = operations;
    }

  }
}
