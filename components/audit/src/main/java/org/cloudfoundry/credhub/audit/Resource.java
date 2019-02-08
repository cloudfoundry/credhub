package org.cloudfoundry.credhub.audit;

public class Resource {
  private final String resourceName;
  private final String resourceId;

  public Resource(final String name, final String id) {
    super();
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
