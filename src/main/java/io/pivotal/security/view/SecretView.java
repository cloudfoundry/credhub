package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.NamedStringSecret;

import java.time.Instant;
import java.util.UUID;

public class SecretView extends BaseView {

  private UUID uuid;
  private String name;

  protected SecretView(Instant versionCreatedAt, UUID uuid, String name) {
    super(versionCreatedAt);
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

  public static SecretView fromEntity(NamedSecret namedSecret) {
    SecretView result;
    if (NamedStringSecret.class.isInstance(namedSecret)) {
      result =  new StringView((NamedStringSecret) namedSecret);
    } else if (NamedCertificateSecret.class.isInstance(namedSecret)) {
      result = new CertificateView((NamedCertificateSecret) namedSecret);
    } else if (NamedSshSecret.class.isInstance(namedSecret)) {
      result = new SshView((NamedSshSecret) namedSecret);
    } else if (NamedRsaSecret.class.isInstance(namedSecret)) {
      result = new RsaView((NamedRsaSecret) namedSecret);
    } else {
      throw new IllegalArgumentException();
    }
    result.setVersionCreatedAt(namedSecret.getVersionCreatedAt());
    result.setUuid(namedSecret.getUuid());
    return result;
  }
}
