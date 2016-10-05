package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedRsaSecret;

import java.time.Instant;

public class RsaSecret extends Secret {
  @JsonProperty("value")
  private RsaBody rsaBody;

  public RsaSecret(Instant updatedAt, String uuid, String publicKey, String privateKey) {
    super(updatedAt, uuid);
    setRsaBody(new RsaBody(publicKey, privateKey));
  }

  public RsaSecret(NamedRsaSecret namedRsaSecret) {
    this(namedRsaSecret.getUpdatedAt(), namedRsaSecret.getUuid(), namedRsaSecret.getPublicKey(), namedRsaSecret.getPrivateKey());
  }

  @Override
  public String getType() {
    return "rsa";
  }

  public RsaBody getRsaBody() {
    return rsaBody;
  }

  public RsaSecret setRsaBody(RsaBody rsaBody) {
    this.rsaBody = rsaBody;
    return this;
  }
}
