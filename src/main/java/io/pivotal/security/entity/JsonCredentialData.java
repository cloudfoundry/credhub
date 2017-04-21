package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue(JsonCredentialData.CREDENTIAL_TYPE)
public class JsonCredentialData extends CredentialData<JsonCredentialData> {

  public static final String CREDENTIAL_TYPE = "json";

  public JsonCredentialData() {
  }

  public JsonCredentialData(String name) {
    super(name);
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
