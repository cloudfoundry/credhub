package org.cloudfoundry.credhub.auth;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.time.Instant;

public class UserContext {

  public static final String VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE = null;
  public static final String AUTH_METHOD_UAA = "uaa";
  public static final String AUTH_METHOD_MUTUAL_TLS = "mutual_tls";
  private static final String UAA_USER_ACTOR_PREFIX = "uaa-user";
  private static final String UAA_CLIENT_ACTOR_PREFIX = "uaa-client";
  private static final String MTLS_ACTOR_PREFIX = "mtls";
  private static final String UAA_PASSWORD_GRANT_TYPE = "password";
  private static final String UAA_CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";

  private String userId = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String userName = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String issuer = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private long validFrom = Instant.EPOCH.getEpochSecond();
  private long validUntil = Instant.EPOCH.getEpochSecond();
  private String clientId;
  private String scope = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String grantType = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String authMethod;

  // Needed for UserContextArgumentResolver
  public UserContext() {}

  public UserContext(
      String userId,
      String userName,
      String issuer,
      long validFrom,
      long validUntil,
      String clientId,
      String scope,
      String grantType,
      String authMethod
  ) {
    this.userId = userId;
    this.userName = userName;
    this.issuer = issuer;
    this.validFrom = validFrom;
    this.validUntil = validUntil;
    this.clientId = clientId;
    this.scope = scope;
    this.grantType = grantType;
    this.authMethod = authMethod;
  }

  public UserContext(
      long validFrom,
      long validUntil,
      String clientId,
      String authMethod
  ) {
    this.validFrom = validFrom;
    this.validUntil = validUntil;
    this.clientId = clientId;
    this.authMethod = authMethod;
  }

  public String getUserName() {
    return userName;
  }

  public String getUserId() {
    return userId;
  }

  public String getIssuer() {
    return issuer;
  }

  public long getValidFrom() {
    return validFrom;
  }

  public long getValidUntil() {
    return validUntil;
  }

  public String getClientId() {
    return clientId;
  }

  public String getScope() {
    return scope;
  }

  public String getGrantType() {
    return grantType;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public String getActor() {
    if (AUTH_METHOD_UAA.equals(this.getAuthMethod())) {
      if (UAA_PASSWORD_GRANT_TYPE.equals(this.getGrantType())) {
        return UAA_USER_ACTOR_PREFIX + ":" + this.getUserId();
      } else if (UAA_CLIENT_CREDENTIALS_GRANT_TYPE.equals(this.getGrantType())) {
        return UAA_CLIENT_ACTOR_PREFIX + ":" + this.getClientId();
      }
    }

    if (AUTH_METHOD_MUTUAL_TLS.equals(this.getAuthMethod())) {
      return MTLS_ACTOR_PREFIX + "-" + parseAppIdentifier(this.getClientId());
    }

    return null;
  }

  private String parseAppIdentifier(String subjectDn) {
    final X500Name dnName = new X500Name(subjectDn);
    final RDN[] rdNs = dnName.getRDNs(BCStyle.OU);
    return rdNs[0].getFirst().getValue().toString();
  }
}
