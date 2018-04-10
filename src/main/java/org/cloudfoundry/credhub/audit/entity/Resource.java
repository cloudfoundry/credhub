package org.cloudfoundry.credhub.audit.entity;

public class Resource{
  private String resourceName, resourceId;

  public Resource(String name, String id){
    resourceId = id;
    resourceName = name;
  }

  public String getResourceName() {
    return resourceName;
  }

  public String getResourceId() {
    return resourceId;
  }
}
