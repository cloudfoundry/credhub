package org.cloudfoundry.credhub.audit.entity;

public class Version {
  private String versionId;

  public Version(String id){
    versionId = id;
  }

  public String getVersionId() {
    return versionId;
  }
}
