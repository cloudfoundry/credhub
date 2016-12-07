package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedSshSecret;

import static org.bouncycastle.asn1.x509.ObjectDigestInfo.publicKey;

import java.time.Instant;
import java.util.UUID;

public class SshSecret extends Secret {
  @JsonProperty("value")
  private SshBody sshBody;

  public SshSecret(Instant updatedAt, UUID uuid, String name, String publicKey, String privateKey) {
    super(updatedAt, uuid, name);
    setSshBody(new SshBody(publicKey, privateKey));
  }

  public SshSecret(NamedSshSecret namedSshSecret) {
    this(
        namedSshSecret.getUpdatedAt(),
        namedSshSecret.getUuid(),
        namedSshSecret.getName(),
        namedSshSecret.getPublicKey(),
        namedSshSecret.getPrivateKey()
    );
  }

  @Override
  public String getType() {
    return "ssh";
  }

  public SshBody getSshBody() {
    return sshBody;
  }

  public SshSecret setSshBody(SshBody sshBody) {
    this.sshBody = sshBody;
    return this;
  }
}
