package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.JsonCredentialVersion;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.domain.RsaCredentialVersion;
import io.pivotal.security.domain.SshCredentialVersion;
import io.pivotal.security.domain.UserCredentialVersion;
import io.pivotal.security.domain.ValueCredentialVersion;

import java.time.Instant;
import java.util.UUID;

public class CredentialView<T extends CredentialValue> {

  private Instant versionCreatedAt;
  private UUID uuid;
  private String name;
  private String type;
  private T value;

  CredentialView() { /* Jackson */ }

  CredentialView(Instant versionCreatedAt, UUID uuid, String name, String type, T value) {
    this.versionCreatedAt = versionCreatedAt;
    this.uuid = uuid;
    this.name = name;
    this.type = type;
    this.value = value;
  }

  public static CredentialView fromEntity(CredentialVersion credentialVersion) {
    CredentialView result;
    if (ValueCredentialVersion.class.isInstance(credentialVersion)) {
      result = new ValueView((ValueCredentialVersion) credentialVersion);
    } else if (PasswordCredentialVersion.class.isInstance(credentialVersion)) {
      result = new PasswordView((PasswordCredentialVersion) credentialVersion);
    } else if (CertificateCredentialVersion.class.isInstance(credentialVersion)) {
      result = new CertificateView((CertificateCredentialVersion) credentialVersion);
    } else if (SshCredentialVersion.class.isInstance(credentialVersion)) {
      result = new SshView((SshCredentialVersion) credentialVersion);
    } else if (RsaCredentialVersion.class.isInstance(credentialVersion)) {
      result = new RsaView((RsaCredentialVersion) credentialVersion);
    } else if (JsonCredentialVersion.class.isInstance(credentialVersion)) {
      result = new JsonView((JsonCredentialVersion) credentialVersion);
    } else if (UserCredentialVersion.class.isInstance(credentialVersion)) {
      result = new UserView((UserCredentialVersion) credentialVersion);
    } else {
      throw new IllegalArgumentException();
    }
    return result;
  }

  @JsonProperty("version_created_at")
  public Instant getVersionCreatedAt() {
    return versionCreatedAt;
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
}
