package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;

import java.time.Instant;
import java.util.UUID;

public class SecretView extends BaseView {

  private final UUID uuid;
  private final String name;
  private final String type;
  private final Object value;

  public SecretView(Instant versionCreatedAt, String name) {
    this(versionCreatedAt, null, name, "", "");
  }

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
    return uuid == null ? "" : uuid.toString();
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
    if (NamedValueSecret.class.isInstance(namedSecret)) {
      result = new ValueView((NamedValueSecret) namedSecret);
    } else if (NamedPasswordSecret.class.isInstance(namedSecret)) {
      result = new PasswordView((NamedPasswordSecret) namedSecret);
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
