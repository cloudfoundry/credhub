package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties("security")
public class AuthorizationConfiguration {
  private Authorization authorization;

  public Authorization getAuthorization() {
    return authorization;
  }

  public void setAuthorization(Authorization authorization) {
    this.authorization = authorization;
  }

  public static class Authorization {
    private List<Permission> permissions;

    public List<Permission> getPermissions() {
      return permissions;
    }

    public void setPermissions(List<Permission> permissions) {
      this.permissions = permissions;
    }

    public static class Permission {
      private List<String> actors;
      private List<PermissionOperation> operations;
      private String path;

      public String getPath() {
        return path;
      }

      public void setPath(String path) {
        this.path = path;
      }

      public List<String> getActors() {
        return actors;
      }

      public void setActors(List<String> actors) {
        this.actors = actors;
      }

      public List<PermissionOperation> getOperations() {
        return operations;
      }

      public void setOperations(List<PermissionOperation> operations) {
        this.operations = operations;
      }
    }
  }
}
