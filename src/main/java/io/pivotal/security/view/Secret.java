package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.NamedStringSecret;

import java.time.Instant;
import java.util.UUID;

public class Secret extends BaseView {

  private UUID uuid;
  private String name;

  protected Secret(Instant updatedAt, UUID uuid, String name) {
    super(updatedAt);
    this.uuid = uuid;
    this.name = name;
  }

  @JsonProperty
  public String getType() {
    throw new UnsupportedOperationException();
  }

  @JsonProperty("id")
  public String getUuid() {
    return uuid.toString();
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public void setName(String name) {
    this.name = name;
  }

  public static Secret fromEntity(NamedSecret namedSecret) {
    Secret result;
    if (NamedStringSecret.class.isInstance(namedSecret)) {
      result =  new StringSecret((NamedStringSecret) namedSecret);
    } else if (NamedCertificateSecret.class.isInstance(namedSecret)) {
      result = new CertificateSecret((NamedCertificateSecret) namedSecret);
    } else if (NamedSshSecret.class.isInstance(namedSecret)) {
      result = new SshSecret((NamedSshSecret) namedSecret);
    } else if (NamedRsaSecret.class.isInstance(namedSecret)) {
      result = new RsaSecret((NamedRsaSecret) namedSecret);
    } else {
      throw new IllegalArgumentException();
    }
    result.setUpdatedAt(namedSecret.getUpdatedAt());
    result.setUuid(namedSecret.getUuid());
    return result;
  }
}
