package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sun.istack.internal.NotNull;

public class CertificateSecret {

  @NotNull
  public final String type = "certificate";

  @JsonProperty("certificate")
  public CertificateBody certificateBody;

  public CertificateSecret(String ca, String pub, String priv) {
    certificateBody = new CertificateBody(ca, pub, priv);
  }

//  public static CertificateSecret make(String ca, String pub, String priv) {
//    CertificateSecret certificateSecret = new CertificateSecret();
//    certificateSecret.ca = ca;
//    certificateSecret.pub = pub;
//    certificateSecret.priv = priv;
//    return certificateSecret;
//  }
}
