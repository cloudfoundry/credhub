package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

public class CertificateCredentialView {

  private String name;
  private UUID uuid;

  public CertificateCredentialView() { /* Jackson */ }

  public CertificateCredentialView(String name, UUID uuid){
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
