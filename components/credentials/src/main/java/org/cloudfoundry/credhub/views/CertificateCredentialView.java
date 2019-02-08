package org.cloudfoundry.credhub.views;

import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateCredentialView {

  private String name;
  private UUID uuid;

  public CertificateCredentialView() {
    super(); /* Jackson */
  }

  public CertificateCredentialView(final String name, final UUID uuid) {
    super();
    this.name = name;
    this.uuid = uuid;
  }

  @JsonProperty("id")
  public UUID getUUID() {
    return uuid;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

}
