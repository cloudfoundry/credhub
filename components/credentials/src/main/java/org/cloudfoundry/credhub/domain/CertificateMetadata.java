package org.cloudfoundry.credhub.domain;

import java.util.List;
import java.util.UUID;

public class CertificateMetadata {

  private UUID id;
  private String name;
  private String caName;
  private List<CertificateVersionMetadata> versions;


  public CertificateMetadata(final UUID id, final String name, final String caName,
    final List<CertificateVersionMetadata> versions) {
    this.id = id;
    this.name = name;
    this.caName = caName;
    this.versions = versions;
  }

  public UUID getId() {
    return id;
  }

  public void setId(final UUID id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  public String getCaName() {
    return caName;
  }

  public void setCaName(final String caName) {
    this.caName = caName;
  }

  public List<CertificateVersionMetadata> getVersions() {
    return versions;
  }

  public void setVersions(final List<CertificateVersionMetadata> versions) {
    this.versions = versions;
  }

}
