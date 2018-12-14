package org.cloudfoundry.credhub.audit.entity;

public class Version {
  private final String versionId;

  public Version(final String id) {
    super();
    versionId = id;
  }

  public String getVersionId() {
    return versionId;
  }
}
