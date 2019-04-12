package org.cloudfoundry.credhub.views;

import java.util.List;
import java.util.UUID;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateCredentialView {

  private String name;
  private UUID uuid;
  private List<CertificateVersionView> certificateVersionViews;
  private String signedBy;

  public CertificateCredentialView() {
    super(); /* Jackson */
  }

  public CertificateCredentialView(
    final String name,
    final UUID uuid,
    @NotNull final List<CertificateVersionView> certificateVersionViews,
    final String signedBy) {
    super();
    this.name = name;
    this.uuid = uuid;
    this.certificateVersionViews = certificateVersionViews;
    this.signedBy = signedBy;
  }

  @JsonProperty("id")
  public UUID getUUID() {
    return uuid;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("versions")
  public List<CertificateVersionView> getCertificateVersionViews() {
    return certificateVersionViews;
  }

  @JsonProperty("signed_by")
  public String getSignedBy() {
    return signedBy;
  }
}
