package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.*;

import java.time.Instant;
import java.util.UUID;

public class CredentialView extends BaseView {

  private UUID uuid;
  private String name;
  private String type;
  private Object value;

  CredentialView() { /* Jackson */ }

  public CredentialView(Instant versionCreatedAt, String name) {
    this(versionCreatedAt, null, name, "", "");
  }

  CredentialView(Instant versionCreatedAt, UUID uuid, String name, String type, Object value) {
    super(versionCreatedAt);
    this.uuid = uuid;
    this.name = name;
    this.type = type;
    this.value = value;
  }

  public static CredentialView fromEntity(Credential credential) {
    CredentialView result;
    if (ValueCredential.class.isInstance(credential)) {
      result = new ValueView((ValueCredential) credential);
    } else if (PasswordCredential.class.isInstance(credential)) {
      result = new PasswordView((PasswordCredential) credential);
    } else if (CertificateCredential.class.isInstance(credential)) {
      result = new CertificateView((CertificateCredential) credential);
    } else if (SshCredential.class.isInstance(credential)) {
      result = new SshView((SshCredential) credential);
    } else if (RsaCredential.class.isInstance(credential)) {
      result = new RsaView((RsaCredential) credential);
    } else if (JsonCredential.class.isInstance(credential)) {
      result = new JsonView((JsonCredential) credential);
    } else if (UserCredential.class.isInstance(credential)) {
      result = new UserView((UserCredential) credential);
    } else {
      throw new IllegalArgumentException();
    }
    return result;
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
