package io.pivotal.security.constants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public class KeyPurposeTranslator {
  public static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
  public static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
  public static final String CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
  public static final String EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
  public static final String TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

  public static KeyPurposeId keyPurposeForOid(ASN1ObjectIdentifier oid) {
    switch(oid.getId()) {
      case SERVER_AUTH:
        return KeyPurposeId.id_kp_serverAuth;
      case CLIENT_AUTH:
        return KeyPurposeId.id_kp_clientAuth;
      case CODE_SIGNING:
        return KeyPurposeId.id_kp_codeSigning;
      case EMAIL_PROTECTION:
        return KeyPurposeId.id_kp_emailProtection;
      case TIME_STAMPING:
        return KeyPurposeId.id_kp_timeStamping;
      default:
        return null;
    }
  }
}
