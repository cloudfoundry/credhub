package org.cloudfoundry.credhub.views;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;

public class CredentialView {

  private Instant versionCreatedAt;
  private UUID uuid;
  private String name;
  private String type;
  private CredentialValue value;

  public CredentialView() {
    super(); /* Jackson */
  }

  public CredentialView(
    final Instant versionCreatedAt,
    final UUID uuid,
    final String name,
    final String type,
    final CredentialValue value
  ) {
    super();
    this.versionCreatedAt = versionCreatedAt;
    this.uuid = uuid;
    this.name = name;
    this.type = type;
    this.value = value;
  }

  public static CredentialView fromEntity(final CredentialVersion credentialVersion) {
    return fromEntity(credentialVersion, false);
  }

  public static CredentialView fromEntity(final CredentialVersion credentialVersion, final boolean concatenateCas) {
    final CredentialView result;
      if (credentialVersion instanceof ValueCredentialVersion) {
      result = new ValueView((ValueCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof PasswordCredentialVersion) {
      result = new PasswordView((PasswordCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof CertificateCredentialVersion) {
      result = new CertificateView((CertificateCredentialVersion) credentialVersion, concatenateCas);
    } else if (credentialVersion instanceof SshCredentialVersion) {
      result = new SshView((SshCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof RsaCredentialVersion) {
      result = new RsaView((RsaCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof JsonCredentialVersion) {
      result = new JsonView((JsonCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof UserCredentialVersion) {
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
  public CredentialValue getValue() {
    return value;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final CredentialView that = (CredentialView) o;
    return Objects.equals(versionCreatedAt, that.versionCreatedAt) &&
      Objects.equals(uuid, that.uuid) &&
      Objects.equals(name, that.name) &&
      Objects.equals(type, that.type) &&
      Objects.equals(value, that.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(versionCreatedAt, uuid, name, type, value);
  }
}
