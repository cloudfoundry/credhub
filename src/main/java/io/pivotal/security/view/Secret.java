package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedStringSecret;

import java.time.Instant;

public class Secret extends BaseView {

  private String uuid;

  protected Secret(Instant updatedAt, String uuid) {
    super(updatedAt);
    this.uuid = uuid;
  }

  @JsonProperty
  public String getType() {
    throw new UnsupportedOperationException();
  }

  @JsonProperty("id")
  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  public static Secret fromEntity(NamedSecret namedSecret) {
    Secret result;
    if (NamedStringSecret.class.isInstance(namedSecret)) {
      result =  new StringSecret((NamedStringSecret) namedSecret);
    } else if (NamedCertificateSecret.class.isInstance(namedSecret)) {
      result = new CertificateSecret((NamedCertificateSecret) namedSecret);
    } else {
      throw new IllegalArgumentException();
    }
    result.setUpdatedAt(namedSecret.getUpdatedAt());
    result.setUuid(namedSecret.getUuid());
    return result;
  }
}