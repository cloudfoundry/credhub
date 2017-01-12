package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedRsaSecret;

import java.time.Instant;
import java.util.UUID;

public class RsaView extends SecretView {
  @JsonProperty("value")
  private RsaBody rsaBody;

  public RsaView(Instant versionCreatedAt, UUID uuid, String name, String publicKey, String privateKey) {
    super(versionCreatedAt, uuid, name);
    setRsaBody(new RsaBody(publicKey, privateKey));
  }

  public RsaView(NamedRsaSecret namedRsaSecret) {
    this(
        namedRsaSecret.getVersionCreatedAt(),
        namedRsaSecret.getUuid(),
        namedRsaSecret.getName(),
        namedRsaSecret.getPublicKey(),
        namedRsaSecret.getPrivateKey()
    );
  }

  @Override
  public String getType() {
    return NamedRsaSecret.SECRET_TYPE;
  }

  public RsaBody getRsaBody() {
    return rsaBody;
  }

  public RsaView setRsaBody(RsaBody rsaBody) {
    this.rsaBody = rsaBody;
    return this;
  }
}
