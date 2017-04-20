package io.pivotal.security.credential;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SshKey implements Credential {

  private final String publicKey;
  private final String privateKey;
  private final String publicKeyFingerprint;

  public SshKey(String publicKey, String privateKey, String publicKeyFingerprint) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.publicKeyFingerprint = publicKeyFingerprint;
  }

  @JsonProperty("public_key")
  public String getPublicKey() {
    return publicKey;
  }

  @JsonProperty("private_key")
  public String getPrivateKey() {
    return privateKey;
  }

  @JsonProperty("public_key_fingerprint")
  public String getPublicKeyFingerprint() {
    return publicKeyFingerprint;
  }
}
