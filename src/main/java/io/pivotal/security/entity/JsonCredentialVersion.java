package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(JsonCredentialVersion.CREDENTIAL_TYPE)
public class JsonCredentialVersion extends CredentialVersion<JsonCredentialVersion> {

  public static final String CREDENTIAL_TYPE = "json";

  public JsonCredentialVersion() {
  }

  public JsonCredentialVersion(String name) {
    super(name);
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
