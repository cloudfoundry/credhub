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

  private final UUID uuid;
  private final String name;
  private final String type;
  private final Object value;

  SecretView(Instant versionCreatedAt, UUID uuid, String name, String type, Object value) {
    super(versionCreatedAt);
    this.uuid = uuid;
    this.name = name;
    this.type = type;
    this.value = value;
  }

  @JsonProperty
  public String getType() {
    return type;
  }

  @JsonProperty("id")
  public String getUuid() {
    return uuid.toString();
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("value")
  public Object getValue() {
    return value;
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
    return result;
  }
}
